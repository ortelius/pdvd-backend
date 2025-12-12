// Package database - Handles all interaction with ArangoDB
package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
	"github.com/cenkalti/backoff"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger = InitLogger() // setup the logger

// DBConnection is the structure that defined the database engine and collections
type DBConnection struct {
	Collections map[string]arangodb.Collection
	Database    arangodb.Database
}

// Define a struct to hold the index definition
type indexConfig struct {
	Collection string
	IdxName    string
	IdxField   string
}

var initDone = false          // has the data been initialized
var dbConnection DBConnection // database connection definition

// GetEnvDefault is a convenience function for handling env vars
func GetEnvDefault(key, defVal string) string {
	val, ex := os.LookupEnv(key) // get the env var
	if !ex {                     // not found return default
		return defVal
	}
	return val // return value for env var
}

// InitLogger sets up the Zap Logger to log to the console in a human readable format
func InitLogger() *zap.Logger {
	prodConfig := zap.NewProductionConfig()
	prodConfig.Encoding = "console"
	prodConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	prodConfig.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	logger, _ := prodConfig.Build()
	return logger
}

func dbConnectionConfig(endpoint connection.Endpoint, dbuser string, dbpass string) connection.HttpConfiguration {
	return connection.HttpConfiguration{
		Authentication: connection.NewBasicAuth(dbuser, dbpass),
		Endpoint:       endpoint,
		ContentType:    connection.ApplicationJSON,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 90 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// InitializeDatabase is the function for connecting to the db engine, creating the database and collections
func InitializeDatabase() DBConnection {
	const initialInterval = 10 * time.Second
	const maxInterval = 2 * time.Minute

	var db arangodb.Database
	var collections map[string]arangodb.Collection
	const databaseName = "vulnmgt"

	ctx := context.Background()

	if initDone {
		return dbConnection
	}

	False := false
	True := true
	dbhost := GetEnvDefault("ARANGO_HOST", "localhost")
	dbport := GetEnvDefault("ARANGO_PORT", "8529")
	dbuser := GetEnvDefault("ARANGO_USER", "root")
	dbpass := GetEnvDefault("ARANGO_PASS", "mypassword")
	dburl := GetEnvDefault("ARANGO_URL", "http://"+dbhost+":"+dbport)

	var client arangodb.Client

	//
	// Database connection with backoff retry
	//

	// Configure exponential backoff
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = initialInterval
	bo.MaxInterval = maxInterval
	bo.MaxElapsedTime = 0 // Set to 0 for indefinite retries

	// Retry logic
	err := backoff.RetryNotify(func() error {
		fmt.Println("Attempting to connect to ArangoDB")
		endpoint := connection.NewRoundRobinEndpoints([]string{dburl})
		conn := connection.NewHttpConnection(dbConnectionConfig(endpoint, dbuser, dbpass))

		client = arangodb.NewClient(conn)

		// Ask the version of the server
		versionInfo, err := client.Version(context.Background())
		if err != nil {
			return err
		}

		logger.Sugar().Infof("Database has version '%s' and license '%s'\n", versionInfo.Version, versionInfo.License)
		return nil

	}, bo, func(err error, _ time.Duration) {
		// Optionally, you can add a message here to be printed after each retry
		fmt.Printf("Retrying connection to ArangoDB: %v\n", err)
	})

	if err != nil {
		logger.Sugar().Fatalf("Backoff Error %v\n", err)
	}

	//
	// Database creation
	//

	exists := false
	dblist, _ := client.Databases(ctx)

	for _, dbinfo := range dblist {
		if dbinfo.Name() == databaseName {
			exists = true
			break
		}
	}

	if exists {
		var options arangodb.GetDatabaseOptions
		if db, err = client.GetDatabase(ctx, databaseName, &options); err != nil {
			logger.Sugar().Fatalf("Failed to get Database: %v", err)
		}
	} else {
		if db, err = client.CreateDatabase(ctx, databaseName, nil); err != nil {
			logger.Sugar().Fatalf("Failed to create Database: %v", err)
		}
	}

	//
	// Collection creation for document storage
	//

	collections = make(map[string]arangodb.Collection)
	// We keep "metadata" here so the collection is created
	collectionNames := []string{"release", "sbom", "purl", "cve", "endpoint", "sync", "metadata", "cve_lifecycle"}

	for _, collectionName := range collectionNames {
		var col arangodb.Collection

		exists, _ = db.CollectionExists(ctx, collectionName)
		if exists {
			var options arangodb.GetCollectionOptions
			if col, err = db.GetCollection(ctx, collectionName, &options); err != nil {
				logger.Sugar().Fatalf("Failed to use collection: %v", err)
			}
		} else {
			if col, err = db.CreateCollectionV2(ctx, collectionName, nil); err != nil {
				logger.Sugar().Fatalf("Failed to create collection: %v", err)
			}
		}

		collections[collectionName] = col
	}

	//
	// Edge collection creation
	//

	edgeCollectionNames := []string{"release2sbom", "sbom2purl", "cve2purl"}

	for _, edgeCollectionName := range edgeCollectionNames {
		var col arangodb.Collection

		exists, _ = db.CollectionExists(ctx, edgeCollectionName)
		if exists {
			var options arangodb.GetCollectionOptions
			if col, err = db.GetCollection(ctx, edgeCollectionName, &options); err != nil {
				logger.Sugar().Fatalf("Failed to use edge collection: %v", err)
			}
		} else {
			edgeType := arangodb.CollectionTypeEdge
			if col, err = db.CreateCollectionV2(ctx, edgeCollectionName, &arangodb.CreateCollectionPropertiesV2{
				Type: &edgeType,
			}); err != nil {
				logger.Sugar().Fatalf("Failed to create edge collection: %v", err)
			}
		}

		collections[edgeCollectionName] = col
	}

	//
	// Index creation for document collections
	//

	idxList := []indexConfig{
		// CVE collection indexes
		{Collection: "cve", IdxName: "package_name", IdxField: "affected[*].package.name"},
		{Collection: "cve", IdxName: "package_purl", IdxField: "affected[*].package.purl"},
		{Collection: "cve", IdxName: "cve_osv_id", IdxField: "osv.id"},
		{Collection: "cve", IdxName: "cve_id", IdxField: "id"},
		{Collection: "cve", IdxName: "cve_severity_rating", IdxField: "database_specific.severity_rating"},
		{Collection: "cve", IdxName: "cve_severity_score", IdxField: "database_specific.cvss_base_score"},

		// SBOM collection indexes
		{Collection: "sbom", IdxName: "sbom_contentsha", IdxField: "contentsha"},

		// PURL collection indexes - unique index on base PURL
		{Collection: "purl", IdxName: "purl_idx", IdxField: "purl"},

		// Release collection indexes for composite key lookup (release deduplication)
		{Collection: "release", IdxName: "release_name", IdxField: "name"},
		{Collection: "release", IdxName: "release_version", IdxField: "version"},
		{Collection: "release", IdxName: "release_contentsha", IdxField: "contentsha"},

		// Endpoint collection indexes
		{Collection: "endpoint", IdxName: "endpoint_name", IdxField: "name"},
		{Collection: "endpoint", IdxName: "endpoint_type", IdxField: "endpoint_type"},
		{Collection: "endpoint", IdxName: "endpoint_environment", IdxField: "environment"},

		// Sync collection indexes - supports timestamp-based version tree
		// Ensure synced_at is indexed for Trend Analysis
		{Collection: "sync", IdxName: "sync_release_name", IdxField: "release_name"},
		{Collection: "sync", IdxName: "sync_release_version", IdxField: "release_version"},
		{Collection: "sync", IdxName: "sync_endpoint_name", IdxField: "endpoint_name"},
		{Collection: "sync", IdxName: "sync_synced_at", IdxField: "synced_at"},
		{Collection: "sync", IdxName: "sync_release_version_major", IdxField: "release_version_major"},
		{Collection: "sync", IdxName: "sync_release_version_minor", IdxField: "release_version_minor"},
		{Collection: "sync", IdxName: "sync_release_version_patch", IdxField: "release_version_patch"},

		// Edge collection indexes for optimized traversals
		// CRITICAL: These indexes enable O(log n) lookups in hub-spoke queries with 400K+ CVEs

		// release2sbom indexes - for validating release existence
		{Collection: "release2sbom", IdxName: "release2sbom_from", IdxField: "_from"},
		{Collection: "release2sbom", IdxName: "release2sbom_to", IdxField: "_to"},

		// sbom2purl indexes - starting point for vulnerability queries (10K edges vs 400K CVEs)
		{Collection: "sbom2purl", IdxName: "sbom2purl_from", IdxField: "_from"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_to", IdxField: "_to"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_version", IdxField: "version"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_version_major", IdxField: "version_major"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_version_minor", IdxField: "version_minor"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_version_patch", IdxField: "version_patch"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_ecosystem", IdxField: "ecosystem"},

		// cve2purl indexes - THE MOST CRITICAL for 400K CVE performance
		// The _to index enables O(log n) CVE lookups per PURL instead of O(n) scans
		{Collection: "cve2purl", IdxName: "cve2purl_from", IdxField: "_from"},
		{Collection: "cve2purl", IdxName: "cve2purl_to", IdxField: "_to"},
		{Collection: "cve2purl", IdxName: "cve2purl_introduced_major", IdxField: "introduced_major"},
		{Collection: "cve2purl", IdxName: "cve2purl_introduced_minor", IdxField: "introduced_minor"},
		{Collection: "cve2purl", IdxName: "cve2purl_fixed_major", IdxField: "fixed_major"},
		{Collection: "cve2purl", IdxName: "cve2purl_fixed_minor", IdxField: "fixed_minor"},
		{Collection: "cve2purl", IdxName: "cve2purl_ecosystem", IdxField: "ecosystem"},

		// CVE Lifecycle collection indexes for MTTR queries
		{Collection: "cve_lifecycle", IdxName: "lifecycle_cve_id", IdxField: "cve_id"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_endpoint", IdxField: "endpoint_name"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_release", IdxField: "release_name"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_package", IdxField: "package"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_severity", IdxField: "severity_rating"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_remediated", IdxField: "is_remediated"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_introduced_at", IdxField: "introduced_at"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_remediated_at", IdxField: "remediated_at"},
		{Collection: "cve_lifecycle", IdxName: "lifecycle_disclosed_after", IdxField: "disclosed_after_deployment"},
	}

	for _, idx := range idxList {
		found := false

		if indexes, err := collections[idx.Collection].Indexes(ctx); err == nil {
			for _, index := range indexes {
				if idx.IdxName == index.Name {
					found = true
					break
				}
			}
		}

		if !found {
			// Define the index options
			indexOptions := arangodb.CreatePersistentIndexOptions{
				Unique: &False,
				Sparse: &False,
				Name:   idx.IdxName,
			}

			// Create the index
			_, _, err = collections[idx.Collection].EnsurePersistentIndex(ctx, []string{idx.IdxField}, &indexOptions)
			if err != nil {
				logger.Sugar().Fatalln("Error creating index:", err)
			} else {
				logger.Sugar().Infof("Created index: %s on %s.%s", idx.IdxName, idx.Collection, idx.IdxField)
			}
		}
	}

	//
	// Create composite indexes (multi-field indexes)
	//

	// Composite index for release lookup by name + version
	releaseNameVersionIdx := "release_name_version"
	found := false
	if indexes, err := collections["release"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if releaseNameVersionIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   releaseNameVersionIdx,
		}
		_, _, err = collections["release"].EnsurePersistentIndex(ctx, []string{"name", "version"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on release", releaseNameVersionIdx)
		}
	}

	// Composite index for sbom2purl edge lookup by _to + version
	sbom2purlToVersionIdx := "sbom2purl_to_version"
	found = false
	if indexes, err := collections["sbom2purl"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if sbom2purlToVersionIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   sbom2purlToVersionIdx,
		}
		_, _, err = collections["sbom2purl"].EnsurePersistentIndex(ctx, []string{"_to", "version"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on sbom2purl", sbom2purlToVersionIdx)
		}
	}

	// Composite index for semantic version sorting
	releaseVersionSortIdx := "release_version_sort"
	found = false
	if indexes, err := collections["release"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if releaseVersionSortIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &True, // Sparse because older records may not have these fields
			Name:   releaseVersionSortIdx,
		}
		_, _, err = collections["release"].EnsurePersistentIndex(ctx,
			[]string{"name", "version_major", "version_minor", "version_patch"},
			&compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on release", releaseVersionSortIdx)
		}
	}

	// Composite index for sync lookup by release name + version

	sbom2purlVersionCompIdx := "sbom2purl_to_version_components"
	found = false
	if indexes, err := collections["sbom2purl"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if sbom2purlVersionCompIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &True,
			Name:   sbom2purlVersionCompIdx,
		}
		_, _, err = collections["sbom2purl"].EnsurePersistentIndex(ctx, []string{"_to", "version_major", "version_minor", "version_patch"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on sbom2purl", sbom2purlVersionCompIdx)
		}
	}

	cve2purlIntroducedVersionIdx := "cve2purl_introduced_version"
	found = false
	if indexes, err := collections["cve2purl"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if cve2purlIntroducedVersionIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &True,
			Name:   cve2purlIntroducedVersionIdx,
		}
		_, _, err = collections["cve2purl"].EnsurePersistentIndex(ctx, []string{"introduced_major", "introduced_minor", "introduced_patch"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on cve2purl", cve2purlIntroducedVersionIdx)
		}
	}

	cve2purlFixedVersionIdx := "cve2purl_fixed_version"
	found = false
	if indexes, err := collections["cve2purl"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if cve2purlFixedVersionIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &True,
			Name:   cve2purlFixedVersionIdx,
		}
		_, _, err = collections["cve2purl"].EnsurePersistentIndex(ctx, []string{"fixed_major", "fixed_minor", "fixed_patch"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on cve2purl", cve2purlFixedVersionIdx)
		}
	}

	syncReleaseIdx := "sync_release_name_version"
	found = false
	if indexes, err := collections["sync"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if syncReleaseIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   syncReleaseIdx,
		}
		_, _, err = collections["sync"].EnsurePersistentIndex(ctx, []string{"release_name", "release_version"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on sync", syncReleaseIdx)
		}
	}

	// Composite index for sync lookup by endpoint + timestamp (for version tree queries)
	syncEndpointTimestampIdx := "sync_endpoint_timestamp"
	found = false
	if indexes, err := collections["sync"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if syncEndpointTimestampIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   syncEndpointTimestampIdx,
		}
		_, _, err = collections["sync"].EnsurePersistentIndex(ctx, []string{"endpoint_name", "synced_at"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on sync", syncEndpointTimestampIdx)
		}
	}

	// Composite index for sync version sorting by endpoint
	syncVersionSortIdx := "sync_version_sort"
	found = false
	if indexes, err := collections["sync"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if syncVersionSortIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &True,
			Name:   syncVersionSortIdx,
		}
		_, _, err = collections["sync"].EnsurePersistentIndex(ctx, []string{"endpoint_name", "release_name", "release_version_major", "release_version_minor", "release_version_patch"}, &compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on sync", syncVersionSortIdx)
		}
	}

	// Unique index on endpoint name to prevent duplicates
	endpointUniqueIdx := "endpoint_name_unique"
	found = false
	if indexes, err := collections["endpoint"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if endpointUniqueIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		uniqueIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &True,
			Sparse: &False,
			Name:   endpointUniqueIdx,
		}
		_, _, err = collections["endpoint"].EnsurePersistentIndex(ctx, []string{"name"}, &uniqueIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating unique index on endpoint name:", err)
		} else {
			logger.Sugar().Infof("Created unique index: %s on endpoint", endpointUniqueIdx)
		}
	}

	// Unique index on PURL to prevent duplicates
	purlUniqueIdx := "purl_unique"
	found = false
	if indexes, err := collections["purl"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if purlUniqueIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		True := true
		uniqueIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &True,
			Sparse: &False,
			Name:   purlUniqueIdx,
		}
		_, _, err = collections["purl"].EnsurePersistentIndex(ctx, []string{"purl"}, &uniqueIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating unique index on purl:", err)
		} else {
			logger.Sugar().Infof("Created unique index: %s on purl", purlUniqueIdx)
		}
	}

	// Composite index for MTTR queries - filter by remediation status, severity, and date
	lifecycleMTTRIdx := "lifecycle_mttr_query"
	found = false
	if indexes, err := collections["cve_lifecycle"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if lifecycleMTTRIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   lifecycleMTTRIdx,
		}
		_, _, err = collections["cve_lifecycle"].EnsurePersistentIndex(ctx,
			[]string{"is_remediated", "severity_rating", "remediated_at"},
			&compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on cve_lifecycle", lifecycleMTTRIdx)
		}
	}

	// Composite index for endpoint-specific CVE tracking
	lifecycleEndpointCVEIdx := "lifecycle_endpoint_cve"
	found = false
	if indexes, err := collections["cve_lifecycle"].Indexes(ctx); err == nil {
		for _, index := range indexes {
			if lifecycleEndpointCVEIdx == index.Name {
				found = true
				break
			}
		}
	}
	if !found {
		compositeIdxOptions := arangodb.CreatePersistentIndexOptions{
			Unique: &False,
			Sparse: &False,
			Name:   lifecycleEndpointCVEIdx,
		}
		_, _, err = collections["cve_lifecycle"].EnsurePersistentIndex(ctx,
			[]string{"endpoint_name", "cve_id", "package", "release_name", "is_remediated"},
			&compositeIdxOptions)
		if err != nil {
			logger.Sugar().Fatalln("Error creating composite index:", err)
		} else {
			logger.Sugar().Infof("Created composite index: %s on cve_lifecycle", lifecycleEndpointCVEIdx)
		}
	}

	initDone = true

	dbConnection = DBConnection{
		Database:    db,
		Collections: collections,
	}

	logger.Sugar().Infof("Database initialization complete with version-aware indexes and CVE lifecycle tracking")

	return dbConnection
}

// FindReleaseByCompositeKey checks if a release exists by name, version, and content SHA
func FindReleaseByCompositeKey(ctx context.Context, db arangodb.Database, name, version, contentSha string) (string, error) {
	query := `
		FOR r IN release
			FILTER r.name == @name 
			   AND r.version == @version 
			   AND r.contentsha == @contentsha
			LIMIT 1
			RETURN r._key
	`
	bindVars := map[string]interface{}{
		"name":       name,
		"version":    version,
		"contentsha": contentSha,
	}

	cursor, err := db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return "", err
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var key string
		_, err := cursor.ReadDocument(ctx, &key)
		if err != nil {
			return "", err
		}
		return key, nil
	}

	return "", nil
}

// FindSBOMByContentHash checks if an SBOM exists by content hash
func FindSBOMByContentHash(ctx context.Context, db arangodb.Database, contentHash string) (string, error) {
	query := `
		FOR s IN sbom
			FILTER s.contentsha == @hash
			LIMIT 1
			RETURN s._key
	`
	bindVars := map[string]interface{}{
		"hash": contentHash,
	}

	cursor, err := db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return "", err
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var key string
		_, err := cursor.ReadDocument(ctx, &key)
		if err != nil {
			return "", err
		}
		return key, nil
	}

	return "", nil
}

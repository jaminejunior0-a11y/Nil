// nil.c - NIL v4.0: Code Intelligence Engine with SID Integration
// Watches code, extracts patterns, logs decisions, builds knowledge graph
// Terminal session capture, error parsing, SID resume strings
// Compile: gcc -O3 -Wall -pthread -o nil nil.c -lsqlite3 -lssl -lcrypto -lm -lcurl -ljson-c -ldl -lpcre2-8
// For Termux: pkg install gcc sqlite openssl curl libjson-c pcre2 make

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <ctype.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <math.h>
#include <limits.h>

#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <pcre2.h>
#include <json-c/json.h>

#define NIL_VERSION "4.0.0"
#define NIL_MAX_PATH 1024
#define NIL_MAX_SID 256
#define NIL_MAX_KEY 256
#define NIL_MAX_VALUE 4096
#define NIL_MAX_RATIONALE 8192
#define NIL_MAX_JSON 65536
#define NIL_MAX_DEPTH 10
#define NIL_SERVER_PORT 8000
#define NIL_EMBEDDING_DIM 128
#define NIL_MAX_FUNCTIONS 1000
#define NIL_MAX_VARIABLES 2000
#define NIL_MAX_PATTERNS 64
#define NIL_MAX_TERMINAL_LINES 10000
#define NIL_WATCH_MASK (IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO)

static char nil_home[NIL_MAX_PATH] = {0};
static char nil_db_path[NIL_MAX_PATH] = {0};
static char nil_llm_endpoint[256] = "http://localhost:11434/api/generate";
static char nil_llm_model[64] = "llama2";
static unsigned char nil_encryption_key[32];

// ============================================================================
// Data Structures
// ============================================================================

typedef enum {
    DECISION_HUMAN,
    DECISION_AI,
    DECISION_AUTONOMOUS,
    DECISION_CONFLICT_RESOLUTION,
    DECISION_PLUGIN,
    DECISION_TERMINAL_PARSE,
    DECISION_SID_IMPORT
} decision_source_t;

typedef struct {
    char node_id[64];
    char sid[NIL_MAX_SID];
    char action[32];
    char key[NIL_MAX_KEY];
    char value[NIL_MAX_VALUE];
    char rationale[NIL_MAX_RATIONALE];
    int64_t timestamp;
    double confidence;
    char source_model[64];
    decision_source_t source;
} decision_t;

typedef struct {
    char name[256];
    char type[64];
    int line_number;
    char signature[512];
} function_entry_t;

typedef struct {
    char name[256];
    char data_type[64];
    char scope[32];
    int line_number;
} variable_entry_t;

typedef struct {
    char file_path[NIL_MAX_PATH];
    char language[32];
    time_t last_modified;
    int lines_of_code;
    char content_hash[65];
    function_entry_t functions[NIL_MAX_FUNCTIONS];
    int function_count;
    variable_entry_t variables[NIL_MAX_VARIABLES];
    int variable_count;
    float embedding[NIL_EMBEDDING_DIM];
} code_snapshot_t;

typedef struct {
    char pattern_name[256];
    char regex[512];
    char language[32];
    char extract_action[64];
    char log_key[256];
    char log_template[512];
    pcre2_code *compiled;
} extraction_template_t;

typedef struct {
    char sid[NIL_MAX_SID];
    char watch_path[NIL_MAX_PATH];
    int inotify_fd;
    int watch_fd;
    pthread_t thread;
    volatile sig_atomic_t running;
} watch_session_t;

typedef struct {
    char session_id[65];
    char sid[NIL_MAX_SID];
    char command[256];
    char output[NIL_MAX_JSON];
    char cwd[NIL_MAX_PATH];
    int exit_code;
    time_t timestamp;
} terminal_session_t;

typedef struct {
    char error_type[64];
    char message[512];
    char file_path[NIL_MAX_PATH];
    int line_number;
    char command[256];
    int exit_code;
} terminal_error_t;

typedef struct {
    char name[256];
    char value[512];
    char constraint[256];
} sid_assumption_t;

typedef struct {
    char name[256];
    char condition[512];
} sid_invariant_t;

typedef struct {
    char version[16];
    sid_assumption_t assumptions[256];
    int assumption_count;
    sid_invariant_t invariants[64];
    int invariant_count;
    char metadata[1024];
} sid_package_t;

// ============================================================================
// Global State
// ============================================================================

static sqlite3 *nil_db = NULL;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t scene_stack_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t template_mutex = PTHREAD_MUTEX_INITIALIZER;
static extraction_template_t *templates = NULL;
static int template_count = 0;

// ============================================================================
// Forward Declarations
// ============================================================================

static void db_lock(void);
static void db_unlock(void);
static int nil_db_init(void);
static int nil_db_insert_decision(decision_t *d);
static void compute_text_embedding(const char *text, float *embedding);
static float cosine_similarity(const float *a, const float *b);
static char *call_llm(const char *prompt, const char *system_prompt);
static void sha256_file(const char *path, char out[65]);
static void sha256_string(const char *str, char out[65]);
static int file_exists(const char *path);
static int is_source_file(const char *path);
static const char *detect_language(const char *path);
static int count_lines(const char *path);
static void nil_init_home(void);
static int load_template(const char *path);
static int load_all_templates(void);
static void create_default_templates(void);
static code_snapshot_t *analyze_file(const char *file_path, const char *sid);
static int index_directory(const char *path, const char *sid);
static watch_session_t *nil_watch_start(const char *sid, const char *path);
static void nil_watch_stop(watch_session_t *session);
static char *generate_report(const char *sid);
static int nil_similar_code(const char *query, const char *sid, char **results);
static int nil_parse_terminal(const char *terminal_file, const char *sid);
static char *nil_resume_session(const char *sid);
static int nil_import_sid(const char *sid_string, const char *sid);
static void extract_patterns(const char *file_path, const char *content, code_snapshot_t *snap, const char *sid);

// ============================================================================
// Utilities
// ============================================================================

static void db_lock(void) { pthread_mutex_lock(&db_mutex); }
static void db_unlock(void) { pthread_mutex_unlock(&db_mutex); }

static void sha256_string(const char *str, char out[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str, strlen(str), hash);
    for (int i = 0; i < 32; i++) sprintf(out + (i * 2), "%02x", hash[i]);
    out[64] = '\0';
}

static void sha256_file(const char *path, char out[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) { out[0] = '\0'; return; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) EVP_DigestUpdate(ctx, buf, n);
    fclose(f);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int len;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++) sprintf(out + (i * 2), "%02x", hash[i]);
    out[64] = '\0';
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int is_source_file(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    return (strcasecmp(ext, ".c") == 0 || strcasecmp(ext, ".h") == 0 ||
            strcasecmp(ext, ".py") == 0 || strcasecmp(ext, ".js") == 0 ||
            strcasecmp(ext, ".java") == 0 || strcasecmp(ext, ".go") == 0 ||
            strcasecmp(ext, ".rs") == 0);
}

static const char *detect_language(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "unknown";
    if (strcasecmp(ext, ".c") == 0 || strcasecmp(ext, ".h") == 0) return "c";
    if (strcasecmp(ext, ".py") == 0) return "python";
    if (strcasecmp(ext, ".js") == 0) return "javascript";
    if (strcasecmp(ext, ".java") == 0) return "java";
    if (strcasecmp(ext, ".go") == 0) return "go";
    if (strcasecmp(ext, ".rs") == 0) return "rust";
    return "unknown";
}

static int count_lines(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int lines = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') lines++;
    fclose(f);
    return lines;
}

static void nil_init_home(void) {
    if (nil_home[0] == '\0') {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(nil_home, sizeof(nil_home), "%s/.nil", home);
        snprintf(nil_db_path, sizeof(nil_db_path), "%s/nil.db", nil_home);
        char *ollama = getenv("NIL_OLLAMA_URL");
        if (ollama) strncpy(nil_llm_endpoint, ollama, 255);
        char *model = getenv("NIL_MODEL");
        if (model) strncpy(nil_llm_model, model, 63);
        char keypath[NIL_MAX_PATH];
        snprintf(keypath, sizeof(keypath), "%s/.key", nil_home);
        FILE *kf = fopen(keypath, "rb");
        if (kf) {
            fread(nil_encryption_key, 1, 32, kf);
            fclose(kf);
        } else {
            RAND_bytes(nil_encryption_key, 32);
            kf = fopen(keypath, "wb");
            if (kf) {
                fwrite(nil_encryption_key, 1, 32, kf);
                fclose(kf);
                chmod(keypath, 0600);
            }
        }
    }
}

// ============================================================================
// Base64 Encoding/Decoding for SID
// ============================================================================

static char *base64_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char *result = malloc(bptr->length + 1);
    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';
    BIO_free_all(b64);
    return result;
}

static unsigned char *base64_decode(const char *data, size_t *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new_mem_buf((void*)data, strlen(data));
    BIO_push(b64, mem);
    unsigned char *buf = malloc(strlen(data));
    int len = BIO_read(b64, buf, strlen(data));
    *out_len = len;
    BIO_free_all(b64);
    return buf;
}

// ============================================================================
// Embeddings
// ============================================================================

static void compute_text_embedding(const char *text, float *embedding) {
    memset(embedding, 0, sizeof(float) * NIL_EMBEDDING_DIM);
    if (!text || !*text) return;
    char *copy = strdup(text);
    char *token = strtok(copy, " \t\n\r,.!?;:()[]{}<>/=+-*\"\'");
    while (token && strlen(token) > 0) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)token, strlen(token), hash);
        for (int i = 0; i < NIL_EMBEDDING_DIM / 32; i++) {
            int idx = abs((int)((hash[i*4] << 24) | (hash[i*4+1] << 16) | 
                         (hash[i*4+2] << 8) | hash[i*4+3])) % NIL_EMBEDDING_DIM;
            embedding[idx] += 1.0f;
        }
        token = strtok(NULL, " \t\n\r,.!?;:()[]{}<>/=+-*\"\'");
    }
    free(copy);
    float norm = 0;
    for (int i = 0; i < NIL_EMBEDDING_DIM; i++) norm += embedding[i] * embedding[i];
    if (norm > 0) {
        norm = sqrtf(norm);
        for (int i = 0; i < NIL_EMBEDDING_DIM; i++) embedding[i] /= norm;
    }
}

static float cosine_similarity(const float *a, const float *b) {
    float dot = 0, na = 0, nb = 0;
    for (int i = 0; i < NIL_EMBEDDING_DIM; i++) {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    return dot / (sqrtf(na) * sqrtf(nb) + 1e-8f);
}

// ============================================================================
// LLM Integration
// ============================================================================

static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response = (char**)userp;
    size_t oldlen = *response ? strlen(*response) : 0;
    char *newptr = realloc(*response, oldlen + realsize + 1);
    if (!newptr) return 0;
    *response = newptr;
    memcpy(*response + oldlen, contents, realsize);
    (*response)[oldlen + realsize] = '\0';
    return realsize;
}

static char *call_llm(const char *prompt, const char *system_prompt) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "model", json_object_new_string(nil_llm_model));
    json_object_object_add(request, "prompt", json_object_new_string(prompt));
    json_object_object_add(request, "stream", json_object_new_boolean(0));
    if (system_prompt && *system_prompt)
        json_object_object_add(request, "system", json_object_new_string(system_prompt));
    const char *json_str = json_object_to_json_string(request);
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    char *response = calloc(1, 1);
    curl_easy_setopt(curl, CURLOPT_URL, nil_llm_endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(curl);
    char *result = NULL;
    if (res == CURLE_OK && response && strlen(response) > 0) {
        struct json_object *parsed = json_tokener_parse(response);
        if (parsed) {
            struct json_object *response_text;
            if (json_object_object_get_ex(parsed, "response", &response_text))
                result = strdup(json_object_get_string(response_text));
            json_object_put(parsed);
        }
    }
    free(response);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(request);
    return result;
}

// ============================================================================
// Database
// ============================================================================

static int nil_db_init(void) {
    nil_init_home();
    mkdir(nil_home, 0755);
    char templates_dir[NIL_MAX_PATH];
    snprintf(templates_dir, sizeof(templates_dir), "%s/templates", nil_home);
    mkdir(templates_dir, 0755);
    char analysis_dir[NIL_MAX_PATH];
    snprintf(analysis_dir, sizeof(analysis_dir), "%s/analysis", nil_home);
    mkdir(analysis_dir, 0755);
    char sid_dir[NIL_MAX_PATH];
    snprintf(sid_dir, sizeof(sid_dir), "%s/sid", nil_home);
    mkdir(sid_dir, 0755);
    char terminal_dir[NIL_MAX_PATH];
    snprintf(terminal_dir, sizeof(terminal_dir), "%s/terminal", nil_home);
    mkdir(terminal_dir, 0755);

    db_lock();
    int rc = sqlite3_open(nil_db_path, &nil_db);
    if (rc == SQLITE_OK) {
        char *err = NULL;
        const char *schema =
            "CREATE TABLE IF NOT EXISTS decisions ("
            "node_id TEXT PRIMARY KEY, sid TEXT, action TEXT, key TEXT, value TEXT, "
            "rationale TEXT, timestamp INTEGER, confidence REAL, source_model TEXT, "
            "source INTEGER DEFAULT 0, parent_node_id TEXT, rollback_plan TEXT, embedding BLOB);"
            "CREATE TABLE IF NOT EXISTS code_snapshots ("
            "file_path TEXT PRIMARY KEY, sid TEXT, language TEXT, last_modified INTEGER, "
            "lines_of_code INTEGER, content_hash TEXT, embedding BLOB);"
            "CREATE TABLE IF NOT EXISTS code_patterns ("
            "pattern_id INTEGER PRIMARY KEY, sid TEXT, file_path TEXT, pattern_name TEXT, "
            "matched_text TEXT, line_number INTEGER, timestamp INTEGER, log_key TEXT);"
            "CREATE TABLE IF NOT EXISTS terminal_sessions ("
            "session_id TEXT PRIMARY KEY, sid TEXT, command TEXT, output TEXT, "
            "exit_code INTEGER, timestamp INTEGER, cwd TEXT, embedding BLOB);"
            "CREATE TABLE IF NOT EXISTS terminal_errors ("
            "error_id INTEGER PRIMARY KEY, session_id TEXT, error_type TEXT, "
            "file_path TEXT, line_number INTEGER, message TEXT, stack_trace TEXT, "
            "command TEXT, exit_code INTEGER, timestamp INTEGER);"
            "CREATE TABLE IF NOT EXISTS sid_packages ("
            "package_id TEXT PRIMARY KEY, sid TEXT, sid_string TEXT, version TEXT, "
            "checksum TEXT, assumptions TEXT, invariants TEXT, metadata TEXT, "
            "timestamp INTEGER);"
            "CREATE TABLE IF NOT EXISTS analysis_reports ("
            "report_id TEXT PRIMARY KEY, sid TEXT, generated_at INTEGER, report_text TEXT, metrics TEXT);"
            "CREATE INDEX IF NOT EXISTS idx_sid_time ON decisions(sid, timestamp DESC);"
            "CREATE INDEX IF NOT EXISTS idx_file ON code_snapshots(file_path);"
            "CREATE INDEX IF NOT EXISTS idx_pattern ON code_patterns(pattern_name, sid);"
            "CREATE INDEX IF NOT EXISTS idx_terminal ON terminal_sessions(timestamp DESC);"
            "CREATE VIRTUAL TABLE IF NOT EXISTS code_fts USING fts5(file_path, content, sid);"
            "CREATE VIRTUAL TABLE IF NOT EXISTS terminal_fts USING fts5(command, output, session_id);";
        sqlite3_exec(nil_db, schema, NULL, NULL, &err);
        if (err) sqlite3_free(err);
    }
    db_unlock();
    return (rc == SQLITE_OK) ? 0 : -1;
}

static int nil_db_insert_decision(decision_t *d) {
    float embedding[NIL_EMBEDDING_DIM];
    char text[2048];
    snprintf(text, sizeof(text), "%s %s %s", d->key, d->value, d->rationale);
    compute_text_embedding(text, embedding);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO decisions (node_id, sid, action, key, value, rationale, "
                      "timestamp, confidence, source_model, source, parent_node_id, rollback_plan, embedding) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
    int rc = -1;
    db_lock();
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, d->node_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, d->sid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, d->action, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, d->key, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, d->value, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, d->rationale, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, d->timestamp);
        sqlite3_bind_double(stmt, 8, d->confidence);
        sqlite3_bind_text(stmt, 9, d->source_model, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 10, d->source);
        sqlite3_bind_text(stmt, 11, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, "", -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 13, embedding, sizeof(embedding), SQLITE_STATIC);
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return rc;
}

static int nil_db_insert_terminal_session(terminal_session_t *session) {
    float embedding[NIL_EMBEDDING_DIM];
    char text[4096];
    snprintf(text, sizeof(text), "%s %s", session->command, session->output);
    compute_text_embedding(text, embedding);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO terminal_sessions VALUES (?,?,?,?,?,?,?,?)";
    int rc = -1;
    db_lock();
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, session->session_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, session->sid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, session->command, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, session->output, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 5, session->exit_code);
        sqlite3_bind_int64(stmt, 6, session->timestamp);
        sqlite3_bind_text(stmt, 7, session->cwd, -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 8, embedding, sizeof(embedding), SQLITE_STATIC);
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return rc;
}

static int nil_db_insert_terminal_error(const char *session_id, terminal_error_t *err) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO terminal_errors (session_id, error_type, file_path, line_number, "
                      "message, stack_trace, command, exit_code, timestamp) VALUES (?,?,?,?,?,?,?,?,?)";
    int rc = -1;
    db_lock();
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, err->error_type, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, err->file_path, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, err->line_number);
        sqlite3_bind_text(stmt, 5, err->message, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, err->command, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 8, err->exit_code);
        sqlite3_bind_int64(stmt, 9, time(NULL) * 1000LL);
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return rc;
}

static int nil_db_insert_sid_package(sid_package_t *pkg, const char *sid) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO sid_packages VALUES (?,?,?,?,?,?,?,?,?)";
    int rc = -1;
    db_lock();
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        char pkg_id[65];
        char buf[512];
        snprintf(buf, sizeof(buf), "%s_%s_%lld", sid, pkg->version, (long long)time(NULL));
        sha256_string(buf, pkg_id);
        sqlite3_bind_text(stmt, 1, pkg_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, sid, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, pkg->version, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, "", -1, SQLITE_STATIC);

        struct json_object *assumptions = json_object_new_array();
        for (int i = 0; i < pkg->assumption_count; i++) {
            struct json_object *a = json_object_new_object();
            json_object_object_add(a, "name", json_object_new_string(pkg->assumptions[i].name));
            json_object_object_add(a, "value", json_object_new_string(pkg->assumptions[i].value));
            json_object_object_add(a, "constraint", json_object_new_string(pkg->assumptions[i].constraint));
            json_object_array_add(assumptions, a);
        }
        sqlite3_bind_text(stmt, 6, json_object_to_json_string(assumptions), -1, SQLITE_TRANSIENT);
        json_object_put(assumptions);

        struct json_object *invariants = json_object_new_array();
        for (int i = 0; i < pkg->invariant_count; i++) {
            struct json_object *inv = json_object_new_object();
            json_object_object_add(inv, "name", json_object_new_string(pkg->invariants[i].name));
            json_object_object_add(inv, "condition", json_object_new_string(pkg->invariants[i].condition));
            json_object_array_add(invariants, inv);
        }
        sqlite3_bind_text(stmt, 7, json_object_to_json_string(invariants), -1, SQLITE_TRANSIENT);
        json_object_put(invariants);

        sqlite3_bind_text(stmt, 8, pkg->metadata, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 9, time(NULL) * 1000LL);
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return rc;
}

// ============================================================================
// SID Integration
// ============================================================================

static int sid_parse_string(const char *sid_str, sid_package_t *pkg) {
    memset(pkg, 0, sizeof(sid_package_t));
    char *copy = strdup(sid_str);
    char *parts[4];
    int part_count = 0;
    char *p = copy;
    char *token = strtok(p, ":");
    while (token && part_count < 4) {
        parts[part_count++] = token;
        token = strtok(NULL, ":");
    }
    if (part_count != 4 || strcmp(parts[0], "SID") != 0) {
        free(copy);
        return -1;
    }
    strncpy(pkg->version, parts[1], 15);
    size_t decoded_len;
    unsigned char *decoded = base64_decode(parts[3], &decoded_len);
    if (!decoded) { free(copy); return -1; }
    char *json_str = malloc(decoded_len + 1);
    memcpy(json_str, decoded, decoded_len);
    json_str[decoded_len] = '\0';
    free(decoded);
    struct json_object *parsed = json_tokener_parse(json_str);
    if (!parsed) { free(json_str); free(copy); return -1; }
    struct json_object *assumptions;
    if (json_object_object_get_ex(parsed, "assumptions", &assumptions)) {
        int len = json_object_array_length(assumptions);
        for (int i = 0; i < len && i < 256; i++) {
            struct json_object *a = json_object_array_get_idx(assumptions, i);
            struct json_object *name, *value, *constraint;
            if (json_object_object_get_ex(a, "name", &name))
                strncpy(pkg->assumptions[i].name, json_object_get_string(name), sizeof(pkg->assumptions[0].name) - 1);
            if (json_object_object_get_ex(a, "value", &value))
                strncpy(pkg->assumptions[i].value, json_object_get_string(value), sizeof(pkg->assumptions[0].value) - 1);
            if (json_object_object_get_ex(a, "constraint", &constraint))
                strncpy(pkg->assumptions[i].constraint, json_object_get_string(constraint), sizeof(pkg->assumptions[0].constraint) - 1);
            pkg->assumption_count++;
        }
    }
    struct json_object *invariants;
    if (json_object_object_get_ex(parsed, "invariants", &invariants)) {
        int len = json_object_array_length(invariants);
        for (int i = 0; i < len && i < 64; i++) {
            struct json_object *inv = json_object_array_get_idx(invariants, i);
            struct json_object *name, *condition;
            if (json_object_object_get_ex(inv, "name", &name))
                strncpy(pkg->invariants[i].name, json_object_get_string(name), sizeof(pkg->invariants[0].name) - 1);
            if (json_object_object_get_ex(inv, "condition", &condition))
                strncpy(pkg->invariants[i].condition, json_object_get_string(condition), sizeof(pkg->invariants[0].condition) - 1);
            pkg->invariant_count++;
        }
    }
    struct json_object *metadata;
    if (json_object_object_get_ex(parsed, "metadata", &metadata)) {
        strncpy(pkg->metadata, json_object_to_json_string(metadata), sizeof(pkg->metadata) - 1);
    }
    json_object_put(parsed);
    free(json_str);
    free(copy);
    return 0;
}

static char *sid_generate_string(sid_package_t *pkg) {
    struct json_object *root = json_object_new_object();
    struct json_object *assumptions = json_object_new_array();
    for (int i = 0; i < pkg->assumption_count; i++) {
        struct json_object *a = json_object_new_object();
        json_object_object_add(a, "name", json_object_new_string(pkg->assumptions[i].name));
        json_object_object_add(a, "value", json_object_new_string(pkg->assumptions[i].value));
        json_object_object_add(a, "constraint", json_object_new_string(pkg->assumptions[i].constraint));
        json_object_array_add(assumptions, a);
    }
    json_object_object_add(root, "assumptions", assumptions);
    struct json_object *invariants = json_object_new_array();
    for (int i = 0; i < pkg->invariant_count; i++) {
        struct json_object *inv = json_object_new_object();
        json_object_object_add(inv, "name", json_object_new_string(pkg->invariants[i].name));
        json_object_object_add(inv, "condition", json_object_new_string(pkg->invariants[i].condition));
        json_object_array_add(invariants, inv);
    }
    json_object_object_add(root, "invariants", invariants);
    struct json_object *metadata = json_object_new_object();
    json_object_object_add(metadata, "version", json_object_new_string(NIL_VERSION));
    json_object_object_add(metadata, "generated_at", json_object_new_int64(time(NULL)));
    json_object_object_add(root, "metadata", metadata);
    const char *json_str = json_object_to_json_string(root);
    char *encoded = base64_encode((unsigned char*)json_str, strlen(json_str));
    char *result = malloc(strlen(encoded) + 64);
    snprintf(result, strlen(encoded) + 64, "SID:%s:%s", NIL_VERSION, encoded);
    free(encoded);
    json_object_put(root);
    return result;
}

static sid_package_t *sid_build_from_decisions(const char *sid_filter) {
    sid_package_t *pkg = calloc(1, sizeof(sid_package_t));
    strcpy(pkg->version, NIL_VERSION);
    db_lock();
    sqlite3_stmt *stmt;
    const char *sql = "SELECT key, value, rationale FROM decisions WHERE sid=? ORDER BY timestamp DESC";
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sid_filter, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW && pkg->assumption_count < 256) {
            const char *key = (const char*)sqlite3_column_text(stmt, 0);
            const char *value = (const char*)sqlite3_column_text(stmt, 1);
            const char *rationale = (const char*)sqlite3_column_text(stmt, 2);
            strncpy(pkg->assumptions[pkg->assumption_count].name, key, sizeof(pkg->assumptions[0].name) - 1);
            strncpy(pkg->assumptions[pkg->assumption_count].value, value, sizeof(pkg->assumptions[0].value) - 1);
            if (rationale) strncpy(pkg->assumptions[pkg->assumption_count].constraint, rationale, sizeof(pkg->assumptions[0].constraint) - 1);
            pkg->assumption_count++;
        }
        sqlite3_finalize(stmt);
    }
    const char *err_sql = "SELECT error_type, message, file_path, line_number FROM terminal_errors "
                          "WHERE session_id IN (SELECT session_id FROM terminal_sessions WHERE sid=?) "
                          "ORDER BY timestamp DESC LIMIT 10";
    if (sqlite3_prepare_v2(nil_db, err_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sid_filter, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW && pkg->invariant_count < 64) {
            const char *err_type = (const char*)sqlite3_column_text(stmt, 0);
            const char *msg = (const char*)sqlite3_column_text(stmt, 1);
            const char *file = (const char*)sqlite3_column_text(stmt, 2);
            int line = sqlite3_column_int(stmt, 3);
            snprintf(pkg->invariants[pkg->invariant_count].name, sizeof(pkg->invariants[0].name), "fix_%s", err_type);
            snprintf(pkg->invariants[pkg->invariant_count].condition, sizeof(pkg->invariants[0].condition), "%s at %s:%d - %s", err_type, file, line, msg);
            pkg->invariant_count++;
        }
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return pkg;
}

// ============================================================================
// Terminal Output Parser
// ============================================================================

static int parse_python_traceback(const char *output, terminal_error_t *errors, int max_errors) {
    int count = 0;
    const char *p = output;
    while ((p = strstr(p, "Traceback (most recent call last):")) != NULL && count < max_errors) {
        p += strlen("Traceback (most recent call last):");
        const char *file_line = NULL;
        const char *next_traceback = strstr(p, "Traceback (most recent call last):");
        const char *error_end = strstr(p, "\n\n");
        const char *search_end = next_traceback ? (next_traceback < error_end ? next_traceback : error_end) : error_end;
        if (!search_end) search_end = p + strlen(p);
        const char *scan = p;
        while (scan < search_end) {
            const char *file_match = strstr(scan, "  File \"");
            if (!file_match || file_match >= search_end) break;
            file_line = file_match;
            scan = file_match + 1;
        }
        if (file_line) {
            file_line += strlen("  File \"");
            const char *quote_end = strchr(file_line, '\"');
            if (quote_end) {
                int path_len = quote_end - file_line;
                if (path_len < sizeof(errors[count].file_path)) {
                    memcpy(errors[count].file_path, file_line, path_len);
                    errors[count].file_path[path_len] = '\0';
                }
                const char *line_part = strstr(quote_end, ", line ");
                if (line_part) errors[count].line_number = atoi(line_part + 7);
            }
        }
        const char *error_start = strstr(p, "\n");
        if (error_start) {
            error_start++;
            while (*error_start == ' ' || *error_start == '\n') error_start++;
            const char *colon = strchr(error_start, ':');
            if (colon) {
                int type_len = colon - error_start;
                if (type_len < sizeof(errors[count].error_type)) {
                    memcpy(errors[count].error_type, error_start, type_len);
                    errors[count].error_type[type_len] = '\0';
                }
                const char *msg = colon + 2;
                const char *msg_end = strchr(msg, '\n');
                if (!msg_end) msg_end = msg + strlen(msg);
                int msg_len = msg_end - msg;
                if (msg_len < sizeof(errors[count].message)) {
                    memcpy(errors[count].message, msg, msg_len);
                    errors[count].message[msg_len] = '\0';
                }
            }
        }
        count++;
        p = search_end;
    }
    return count;
}

static int parse_gcc_errors(const char *output, terminal_error_t *errors, int max_errors) {
    int count = 0;
    const char *p = output;
    while (count < max_errors) {
        const char *colon1 = strchr(p, ':');
        if (!colon1) break;
        const char *line_start = colon1;
        while (line_start > p && line_start[-1] != '\n') line_start--;
        int path_len = colon1 - line_start;
        if (path_len > 0 && path_len < sizeof(errors[count].file_path)) {
            memcpy(errors[count].file_path, line_start, path_len);
            errors[count].file_path[path_len] = '\0';
        }
        const char *colon2 = strchr(colon1 + 1, ':');
        if (colon2) {
            errors[count].line_number = atoi(colon1 + 1);
            const char *type_start = colon2 + 1;
            while (*type_start == ' ' || *type_start == ':') type_start++;
            if (strncmp(type_start, "error", 5) == 0) strcpy(errors[count].error_type, "compile_error");
            else if (strncmp(type_start, "warning", 7) == 0) strcpy(errors[count].error_type, "compile_warning");
            const char *msg = strchr(type_start, ':');
            if (msg) {
                msg++;
                while (*msg == ' ') msg++;
                const char *msg_end = strchr(msg, '\n');
                if (!msg_end) msg_end = msg + strlen(msg);
                int msg_len = msg_end - msg;
                if (msg_len < sizeof(errors[count].message)) {
                    memcpy(errors[count].message, msg, msg_len);
                    errors[count].message[msg_len] = '\0';
                }
            }
            count++;
        }
        p = colon1 + 1;
    }
    return count;
}

static int parse_terminal_output(const char *output, const char *command, int exit_code, terminal_error_t *errors, int max_errors) {
    int count = 0;
    if (exit_code != 0) {
        count = parse_python_traceback(output, errors, max_errors);
        if (count == 0) count = parse_gcc_errors(output, errors, max_errors);
        if (count == 0) {
            strncpy(errors[0].error_type, "generic_error", sizeof(errors[0].error_type) - 1);
            strncpy(errors[0].message, "Command failed with non-zero exit code", sizeof(errors[0].message) - 1);
            errors[0].exit_code = exit_code;
            strncpy(errors[0].command, command, sizeof(errors[0].command) - 1);
            count = 1;
        }
    }
    return count;
}

static int nil_parse_terminal(const char *terminal_file, const char *sid) {
    FILE *f = fopen(terminal_file, "r");
    if (!f) {
        printf("Cannot open terminal output file: %s\n", terminal_file);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *content = malloc(size + 1);
    if (!content) { fclose(f); return -1; }
    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    terminal_session_t session = {0};
    session.timestamp = time(NULL);
    getcwd(session.cwd, sizeof(session.cwd));
    strncpy(session.sid, sid, sizeof(session.sid) - 1);

    char *line = strtok(content, "\n");
    if (line) {
        char *cmd_start = line;
        while (*cmd_start && (*cmd_start == '$' || *cmd_start == '~' || *cmd_start == '/' ||
                               *cmd_start == ' ' || *cmd_start == '\t')) cmd_start++;
        strncpy(session.command, cmd_start, sizeof(session.command) - 1);
        char *output_start = line + strlen(line) + 1;
        if (output_start < content + size) {
            strncpy(session.output, output_start, sizeof(session.output) - 1);
        }
    }

    if (strstr(session.output, "error:") || strstr(session.output, "Error:") ||
        strstr(session.output, "ERROR") || strstr(session.output, "Traceback")) {
        session.exit_code = 1;
    }

    char session_id[65];
    char buf[512];
    snprintf(buf, sizeof(buf), "%s_%s_%lld", sid, session.command, (long long)session.timestamp);
    sha256_string(buf, session_id);
    strncpy(session.session_id, session_id, sizeof(session.session_id) - 1);

    nil_db_insert_terminal_session(&session);

    terminal_error_t errors[100];
    int error_count = parse_terminal_output(session.output, session.command, session.exit_code, errors, 100);

    for (int i = 0; i < error_count; i++) {
        nil_db_insert_terminal_error(session_id, &errors[i]);
        decision_t d = {0};
        strcpy(d.action, "terminal_error");
        strcpy(d.key, errors[i].error_type);
        snprintf(d.value, sizeof(d.value), "%s:%d", errors[i].file_path, errors[i].line_number);
        snprintf(d.rationale, sizeof(d.rationale), "Error in %s:%d - %s", errors[i].file_path, errors[i].line_number, errors[i].message);
        d.timestamp = time(NULL) * 1000LL;
        d.confidence = 1.0;
        strcpy(d.source_model, "terminal_parser");
        d.source = DECISION_TERMINAL_PARSE;
        sha256_string(d.rationale, d.node_id);
        nil_db_insert_decision(&d);
        printf("  %s: %s:%d - %.60s...\n", errors[i].error_type, errors[i].file_path, errors[i].line_number, errors[i].message);
    }

    if (error_count == 0 && session.exit_code == 0) {
        printf("  Command succeeded with no errors\n");
    }
    printf("  Parsed %d errors from terminal output\n", error_count);
    free(content);
    return error_count;
}

// ============================================================================
// Session Resume (SID Export)
// ============================================================================

static char *nil_resume_session(const char *sid) {
    sid_package_t *pkg = sid_build_from_decisions(sid);
    if (!pkg) return NULL;

    db_lock();
    sqlite3_stmt *stmt;
    const char *sql = "SELECT file_path, content_hash, language, lines_of_code FROM code_snapshots WHERE sid=?";
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW && pkg->assumption_count < 256) {
            const char *file = (const char*)sqlite3_column_text(stmt, 0);
            const char *hash = (const char*)sqlite3_column_text(stmt, 1);
            const char *lang = (const char*)sqlite3_column_text(stmt, 2);
            int lines = sqlite3_column_int(stmt, 3);
            char key[256], value[512];
            snprintf(key, sizeof(key), "file.%s", file);
            snprintf(value, sizeof(value), "%s:%d:%s", hash, lines, lang);
            strncpy(pkg->assumptions[pkg->assumption_count].name, key, sizeof(pkg->assumptions[0].name) - 1);
            strncpy(pkg->assumptions[pkg->assumption_count].value, value, sizeof(pkg->assumptions[0].value) - 1);
            pkg->assumption_count++;
        }
        sqlite3_finalize(stmt);
    }
    const char *err_sql = "SELECT error_type, message, file_path, line_number FROM terminal_errors "
                          "WHERE session_id IN (SELECT session_id FROM terminal_sessions WHERE sid=?) "
                          "ORDER BY timestamp DESC LIMIT 10";
    if (sqlite3_prepare_v2(nil_db, err_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW && pkg->invariant_count < 64) {
            const char *err_type = (const char*)sqlite3_column_text(stmt, 0);
            const char *msg = (const char*)sqlite3_column_text(stmt, 1);
            const char *file = (const char*)sqlite3_column_text(stmt, 2);
            int line = sqlite3_column_int(stmt, 3);
            snprintf(pkg->invariants[pkg->invariant_count].name, sizeof(pkg->invariants[0].name), "fix_%s", err_type);
            snprintf(pkg->invariants[pkg->invariant_count].condition, sizeof(pkg->invariants[0].condition), "%s at %s:%d - %s", err_type, file, line, msg);
            pkg->invariant_count++;
        }
        sqlite3_finalize(stmt);
    }
    db_unlock();

    struct json_object *meta = json_object_new_object();
    json_object_object_add(meta, "version", json_object_new_string(NIL_VERSION));
    json_object_object_add(meta, "sid", json_object_new_string(sid));
    json_object_object_add(meta, "generated_at", json_object_new_int64(time(NULL)));
    json_object_object_add(meta, "source", json_object_new_string("nil_resume"));
    strncpy(pkg->metadata, json_object_to_json_string(meta), sizeof(pkg->metadata) - 1);
    json_object_put(meta);

    char *sid_str = sid_generate_string(pkg);
    nil_db_insert_sid_package(pkg, sid);
    free(pkg);
    return sid_str;
}

static int nil_import_sid(const char *sid_string, const char *sid) {
    sid_package_t pkg;
    if (sid_parse_string(sid_string, &pkg) != 0) {
        printf("Invalid SID string or checksum mismatch\n");
        return -1;
    }
    printf("SID string valid (version %s, %d assumptions, %d invariants)\n",
           pkg.version, pkg.assumption_count, pkg.invariant_count);
    for (int i = 0; i < pkg.assumption_count; i++) {
        decision_t d = {0};
        strcpy(d.action, "sid_import");
        strncpy(d.key, pkg.assumptions[i].name, sizeof(d.key) - 1);
        strncpy(d.value, pkg.assumptions[i].value, sizeof(d.value) - 1);
        snprintf(d.rationale, sizeof(d.rationale), "Imported from SID: %s", pkg.assumptions[i].constraint);
        d.timestamp = time(NULL) * 1000LL;
        d.confidence = 0.95;
        strcpy(d.source_model, "sid_import");
        d.source = DECISION_SID_IMPORT;
        sha256_string(d.rationale, d.node_id);
        nil_db_insert_decision(&d);
    }
    nil_db_insert_sid_package(&pkg, sid);
    printf("  Imported %d assumptions and %d invariants\n", pkg.assumption_count, pkg.invariant_count);
    return 0;
}

// ============================================================================
// Template Engine
// ============================================================================

static int load_template(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    extraction_template_t *t = realloc(templates, sizeof(extraction_template_t) * (template_count + 1));
    if (!t) { fclose(f); return -1; }
    templates = t;
    extraction_template_t *tmpl = &templates[template_count];
    memset(tmpl, 0, sizeof(extraction_template_t));
    char line[1024];
    char current_section[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                strncpy(current_section, p + 1, sizeof(current_section) - 1);
            }
            continue;
        }
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        while (isspace((unsigned char)*val)) val++;
        while (isspace((unsigned char)key[strlen(key)-1])) key[strlen(key)-1] = '\0';
        if (strcmp(key, "regex") == 0) strncpy(tmpl->regex, val, sizeof(tmpl->regex) - 1);
        else if (strcmp(key, "action") == 0) strncpy(tmpl->extract_action, val, sizeof(tmpl->extract_action) - 1);
        else if (strcmp(key, "key") == 0) strncpy(tmpl->log_key, val, sizeof(tmpl->log_key) - 1);
        else if (strcmp(key, "language") == 0) strncpy(tmpl->language, val, sizeof(tmpl->language) - 1);
    }
    fclose(f);
    if (tmpl->regex[0]) {
        int errornumber;
        PCRE2_SIZE erroroffset;
        tmpl->compiled = pcre2_compile((PCRE2_SPTR)tmpl->regex, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
        if (!tmpl->compiled) {
            fprintf(stderr, "Failed to compile regex for %s\n", current_section);
            return -1;
        }
    }
    strncpy(tmpl->pattern_name, current_section, sizeof(tmpl->pattern_name) - 1);
    template_count++;
    return 0;
}

static int load_all_templates(void) {
    char templates_dir[NIL_MAX_PATH];
    snprintf(templates_dir, sizeof(templates_dir), "%s/templates", nil_home);
    DIR *dir = opendir(templates_dir);
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".template")) {
            char path[NIL_MAX_PATH];
            snprintf(path, sizeof(path), "%s/%s", templates_dir, entry->d_name);
            load_template(path);
        }
    }
    closedir(dir);
    return template_count;
}

static void create_default_templates(void) {
    char templates_dir[NIL_MAX_PATH];
    snprintf(templates_dir, sizeof(templates_dir), "%s/templates", nil_home);
    mkdir(templates_dir, 0755);
    const char *c_template =
        "[pattern:function]\n"
        "regex = ^[a-zA-Z_][a-zA-Z0-9_]*\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*\\([^)]*\\)\\s*\\{\n"
        "action = log\n"
        "key = function.declared\n"
        "language = c\n\n"
        "[pattern:sql_query]\n"
        "regex = (mysql_query|sqlite3_exec|PQexec|pg_query)\\s*\\([^,]*,\\s*\"([^\"]+)\"\n"
        "action = report\n"
        "key = database.query\n"
        "language = c\n\n"
        "[pattern:api_call]\n"
        "regex = (curl_easy_init|http_get|fetch|request)\\s*\\(\n"
        "action = log\n"
        "key = api.called\n"
        "language = c\n";
    char path[NIL_MAX_PATH];
    snprintf(path, sizeof(path), "%s/c.template", templates_dir);
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%s", c_template); fclose(f); }
    const char *py_template =
        "[pattern:function]\n"
        "regex = ^def\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(\n"
        "action = log\n"
        "key = function.declared\n"
        "language = python\n\n"
        "[pattern:sql_query]\n"
        "regex = (cursor\\.execute|db\\.query|session\\.query)\\s*\\(\n"
        "action = report\n"
        "key = database.query\n"
        "language = python\n";
    snprintf(path, sizeof(path), "%s/python.template", templates_dir);
    f = fopen(path, "w");
    if (f) { fprintf(f, "%s", py_template); fclose(f); }
}

// ============================================================================
// Code Analysis
// ============================================================================

static void extract_patterns(const char *file_path, const char *content, code_snapshot_t *snap, const char *sid) {
    pthread_mutex_lock(&template_mutex);
    for (int i = 0; i < template_count; i++) {
        extraction_template_t *t = &templates[i];
        if (t->language[0] && strcmp(t->language, snap->language) != 0) continue;
        if (!t->compiled) continue;
        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(t->compiled, NULL);
        PCRE2_SIZE subject_length = strlen(content);
        int rc;
        PCRE2_SIZE offset = 0;
        while ((rc = pcre2_match(t->compiled, (PCRE2_SPTR)content, subject_length, offset, 0, match_data, NULL)) >= 0) {
            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
            char matched[512];
            PCRE2_SIZE match_len = ovector[1] - ovector[0];
            if (match_len < sizeof(matched)) {
                memcpy(matched, content + ovector[0], match_len);
                matched[match_len] = '\0';
            } else {
                strncpy(matched, content + ovector[0], sizeof(matched) - 1);
            }
            int line = 1;
            for (PCRE2_SIZE j = 0; j < ovector[0]; j++) if (content[j] == '\n') line++;
            if (strcmp(t->extract_action, "log") == 0) {
                decision_t d = {0};
                strcpy(d.action, "pattern_detected");
                strncpy(d.key, t->log_key, sizeof(d.key) - 1);
                strncpy(d.value, matched, sizeof(d.value) - 1);
                snprintf(d.rationale, sizeof(d.rationale), "Pattern '%s' in %s:%d", t->pattern_name, file_path, line);
                d.timestamp = time(NULL) * 1000LL;
                d.confidence = 0.95;
                strcpy(d.source_model, "pattern_engine");
                d.source = DECISION_AUTONOMOUS;
                sha256_string(d.rationale, d.node_id);
                nil_db_insert_decision(&d);
            }
            sqlite3_stmt *stmt;
            const char *sql = "INSERT INTO code_patterns (sid, file_path, pattern_name, matched_text, line_number, timestamp, log_key) VALUES (?,?,?,?,?,?,?)";
            db_lock();
            if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, file_path, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, t->pattern_name, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 4, matched, -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 5, line);
                sqlite3_bind_int64(stmt, 6, time(NULL) * 1000LL);
                sqlite3_bind_text(stmt, 7, t->log_key, -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            db_unlock();
            offset = ovector[1];
            if (offset >= subject_length) break;
        }
        pcre2_match_data_free(match_data);
    }
    pthread_mutex_unlock(&template_mutex);
}

static code_snapshot_t *analyze_file(const char *file_path, const char *sid) {
    FILE *f = fopen(file_path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *content = malloc(size + 1);
    if (!content) { fclose(f); return NULL; }
    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);
    code_snapshot_t *snap = calloc(1, sizeof(code_snapshot_t));
    strncpy(snap->file_path, file_path, sizeof(snap->file_path) - 1);
    strcpy(snap->language, detect_language(file_path));
    snap->last_modified = time(NULL);
    snap->lines_of_code = count_lines(file_path);
    sha256_file(file_path, snap->content_hash);
    compute_text_embedding(content, snap->embedding);
    extract_patterns(file_path, content, snap, sid);
    sqlite3_stmt *stmt;
    const char *fts_sql = "INSERT OR REPLACE INTO code_fts (file_path, content, sid) VALUES (?,?,?)";
    db_lock();
    if (sqlite3_prepare_v2(nil_db, fts_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, file_path, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, content, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, sid, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    db_unlock();
    free(content);
    return snap;
}

static int index_directory(const char *path, const char *sid) {
    DIR *dir = opendir(path);
    if (!dir) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char full_path[NIL_MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                count += index_directory(full_path, sid);
            } else if (is_source_file(full_path)) {
                code_snapshot_t *snap = analyze_file(full_path, sid);
                if (snap) {
                    sqlite3_stmt *stmt;
                    const char *sql = "INSERT OR REPLACE INTO code_snapshots VALUES (?,?,?,?,?,?,?)";
                    db_lock();
                    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, snap->file_path, -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 2, sid, -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 3, snap->language, -1, SQLITE_STATIC);
                        sqlite3_bind_int64(stmt, 4, snap->last_modified);
                        sqlite3_bind_int(stmt, 5, snap->lines_of_code);
                        sqlite3_bind_text(stmt, 6, snap->content_hash, -1, SQLITE_STATIC);
                        sqlite3_bind_blob(stmt, 7, snap->embedding, sizeof(snap->embedding), SQLITE_STATIC);
                        sqlite3_step(stmt);
                        sqlite3_finalize(stmt);
                    }
                    db_unlock();
                    printf("  %s (%d lines, %s)\n", snap->file_path, snap->lines_of_code, snap->language);
                    free(snap);
                    count++;
                }
            }
        }
    }
    closedir(dir);
    return count;
}

// ============================================================================
// File Watcher (Inotify)
// ============================================================================

static void *watch_thread(void *arg) {
    watch_session_t *session = (watch_session_t*)arg;
    char buf[4096];
    printf("Watching %s\n", session->watch_path);
    while (session->running) {
        ssize_t len = read(session->inotify_fd, buf, sizeof(buf));
        if (len <= 0) continue;
        ssize_t i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event*)&buf[i];
            if (event->len > 0 && is_source_file(event->name)) {
                char full_path[NIL_MAX_PATH];
                snprintf(full_path, sizeof(full_path), "%s/%s", session->watch_path, event->name);
                if (event->mask & (IN_MODIFY | IN_CREATE | IN_MOVED_TO)) {
                    printf("[%s] Detected change: %s\n", ctime(&(time_t){time(NULL)}), event->name);
                    code_snapshot_t *snap = analyze_file(full_path, session->sid);
                    if (snap) {
                        sqlite3_stmt *stmt;
                        const char *sql = "INSERT OR REPLACE INTO code_snapshots VALUES (?,?,?,?,?,?,?)";
                        db_lock();
                        if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                            sqlite3_bind_text(stmt, 1, snap->file_path, -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, session->sid, -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 3, snap->language, -1, SQLITE_STATIC);
                            sqlite3_bind_int64(stmt, 4, snap->last_modified);
                            sqlite3_bind_int(stmt, 5, snap->lines_of_code);
                            sqlite3_bind_text(stmt, 6, snap->content_hash, -1, SQLITE_STATIC);
                            sqlite3_bind_blob(stmt, 7, snap->embedding, sizeof(snap->embedding), SQLITE_STATIC);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                        db_unlock();
                        decision_t d = {0};
                        strcpy(d.action, "file_changed");
                        strcpy(d.key, "file.modified");
                        strncpy(d.value, event->name, sizeof(d.value) - 1);
                        snprintf(d.rationale, sizeof(d.rationale), "File %s changed (%d lines)", event->name, snap->lines_of_code);
                        d.timestamp = time(NULL) * 1000LL;
                        d.confidence = 1.0;
                        strcpy(d.source_model, "file_watcher");
                        d.source = DECISION_AUTONOMOUS;
                        sha256_string(d.rationale, d.node_id);
                        nil_db_insert_decision(&d);
                        printf("  Logged: patterns detected\n");
                        free(snap);
                    }
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }
    return NULL;
}

static watch_session_t *nil_watch_start(const char *sid, const char *path) {
    watch_session_t *session = calloc(1, sizeof(watch_session_t));
    strncpy(session->sid, sid, sizeof(session->sid) - 1);
    strncpy(session->watch_path, path, sizeof(session->watch_path) - 1);
    session->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (session->inotify_fd < 0) { free(session); return NULL; }
    session->watch_fd = inotify_add_watch(session->inotify_fd, path, NIL_WATCH_MASK);
    if (session->watch_fd < 0) { close(session->inotify_fd); free(session); return NULL; }
    session->running = 1;
    pthread_create(&session->thread, NULL, watch_thread, session);
    return session;
}

static void nil_watch_stop(watch_session_t *session) {
    if (!session) return;
    session->running = 0;
    pthread_join(session->thread, NULL);
    inotify_rm_watch(session->inotify_fd, session->watch_fd);
    close(session->inotify_fd);
    free(session);
}

// ============================================================================
// AI Report Generation
// ============================================================================

static char *generate_report(const char *sid) {
    int file_count = 0, func_count = 0, query_count = 0, api_count = 0, error_count = 0;
    db_lock();
    sqlite3_stmt *stmt;
    const char *queries[] = {
        "SELECT COUNT(*) FROM code_snapshots WHERE sid=?",
        "SELECT COUNT(*) FROM code_patterns WHERE sid=? AND log_key='function.declared'",
        "SELECT COUNT(*) FROM code_patterns WHERE sid=? AND log_key='database.query'",
        "SELECT COUNT(*) FROM code_patterns WHERE sid=? AND log_key='api.called'",
        "SELECT COUNT(*) FROM terminal_errors WHERE session_id IN (SELECT session_id FROM terminal_sessions WHERE sid=?)"
    };
    int *counts[] = {&file_count, &func_count, &query_count, &api_count, &error_count};
    for (int i = 0; i < 5; i++) {
        if (sqlite3_prepare_v2(nil_db, queries[i], -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) *counts[i] = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }
    db_unlock();
    char prompt[4096];
    snprintf(prompt, sizeof(prompt),
        "Analyze this codebase and provide insights:\n"
        "Files: %d\nFunctions: %d\nDatabase queries: %d\nAPI calls: %d\nTerminal errors: %d\n\n"
        "Provide: 1) Architecture assessment 2) Security concerns 3) Refactoring suggestions",
        file_count, func_count, query_count, api_count, error_count);
    char *analysis = call_llm(prompt, "You are a senior software architect analyzing codebases. Be concise and actionable.");
    char report_id[65];
    char buf[256];
    snprintf(buf, sizeof(buf), "%s_%lld", sid, (long long)time(NULL));
    sha256_string(buf, report_id);
    db_lock();
    if (sqlite3_prepare_v2(nil_db, "INSERT INTO analysis_reports VALUES (?,?,?,?,?)", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, report_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, sid, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, time(NULL) * 1000LL);
        sqlite3_bind_text(stmt, 4, analysis ? analysis : "No analysis generated", -1, SQLITE_STATIC);
        struct json_object *metrics = json_object_new_object();
        json_object_object_add(metrics, "files", json_object_new_int(file_count));
        json_object_object_add(metrics, "functions", json_object_new_int(func_count));
        json_object_object_add(metrics, "queries", json_object_new_int(query_count));
        json_object_object_add(metrics, "api_calls", json_object_new_int(api_count));
        json_object_object_add(metrics, "errors", json_object_new_int(error_count));
        sqlite3_bind_text(stmt, 5, json_object_to_json_string(metrics), -1, SQLITE_TRANSIENT);
        json_object_put(metrics);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return analysis;
}

// ============================================================================
// Similarity Search
// ============================================================================

static int nil_similar_code(const char *query, const char *sid, char **results) {
    float query_emb[NIL_EMBEDDING_DIM];
    compute_text_embedding(query, query_emb);
    typedef struct { char path[NIL_MAX_PATH]; float score; } match_t;
    match_t matches[50];
    int match_count = 0;
    db_lock();
    sqlite3_stmt *stmt;
    const char *sql = "SELECT file_path, embedding FROM code_snapshots WHERE sid=? AND embedding IS NOT NULL";
    if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, sid, -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW && match_count < 50) {
            const char *path = (const char*)sqlite3_column_text(stmt, 0);
            const float *emb = (const float*)sqlite3_column_blob(stmt, 1);
            int emb_size = sqlite3_column_bytes(stmt, 1);
            if (emb && emb_size == sizeof(float) * NIL_EMBEDDING_DIM) {
                float sim = cosine_similarity(query_emb, emb);
                if (sim > 0.25f) {
                    strncpy(matches[match_count].path, path, sizeof(matches[0].path) - 1);
                    matches[match_count].score = sim;
                    match_count++;
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    db_unlock();
    for (int i = 0; i < match_count - 1; i++) {
        for (int j = i + 1; j < match_count; j++) {
            if (matches[j].score > matches[i].score) {
                match_t tmp = matches[i];
                matches[i] = matches[j];
                matches[j] = tmp;
            }
        }
    }
    size_t out_size = NIL_MAX_JSON;
    char *out = malloc(out_size);
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < match_count && i < 10; i++) {
        char line[512];
        snprintf(line, sizeof(line), "  [%.0f%%] %s\n", matches[i].score * 100, matches[i].path);
        size_t ll = strlen(line);
        if (used + ll + 1 < out_size) { strcat(out, line); used += ll; }
    }
    *results = out;
    return match_count;
}

// ============================================================================
// Commands
// ============================================================================

static void cmd_help(void) {
    printf("\nNIL v%s - Code Intelligence Engine with SID Integration\n", NIL_VERSION);
    printf("================================================================\n\n");
    printf("Core Commands:\n");
    printf("  nil init                    Initialize environment\n");
    printf("  nil watch <sid> [path]      Watch code directory for changes\n");
    printf("  nil analyze <file> [sid]    Analyze single file\n");
    printf("  nil index <path> [sid]      Index entire codebase\n");
    printf("  nil report <sid>            Generate AI analysis report\n");
    printf("  nil search <query> [sid]    Search code with embeddings\n\n");
    printf("Terminal Integration:\n");
    printf("  nil parse <file> [sid]      Parse terminal output for errors\n");
    printf("  nil resume [sid]            Generate SID resume string\n");
    printf("  nil import-sid <string>     Import SID assumptions\n\n");
    printf("Template System:\n");
    printf("  nil template create         Create default templates\n\n");
}

static void cmd_init(void) {
    nil_init_home();
    nil_db_init();
    create_default_templates();
    load_all_templates();
    printf("NIL v%s initialized\n", NIL_VERSION);
    printf("Templates: %d loaded\n", template_count);
    printf("Directories: templates/ analysis/ sid/ terminal/\n");
    printf("SID Integration: parse, resume, import-sid\n");
}

static void cmd_status(void) {
    db_lock();
    sqlite3_stmt *stmt;
    int files = 0, patterns = 0, decisions = 0, sessions = 0, errors = 0, sids = 0;
    const char *queries[] = {
        "SELECT COUNT(*) FROM code_snapshots",
        "SELECT COUNT(*) FROM code_patterns",
        "SELECT COUNT(*) FROM decisions",
        "SELECT COUNT(*) FROM terminal_sessions",
        "SELECT COUNT(*) FROM terminal_errors",
        "SELECT COUNT(*) FROM sid_packages"
    };
    int *counts[] = {&files, &patterns, &decisions, &sessions, &errors, &sids};
    for (int i = 0; i < 6; i++) {
        if (sqlite3_prepare_v2(nil_db, queries[i], -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) *counts[i] = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }
    db_unlock();
    printf("\nNIL v%s Status\n", NIL_VERSION);
    printf("===========================\n");
    printf("Files indexed:      %d\n", files);
    printf("Patterns found:     %d\n", patterns);
    printf("Decisions logged:   %d\n", decisions);
    printf("Terminal sessions:  %d\n", sessions);
    printf("Errors parsed:      %d\n", errors);
    printf("SID packages:       %d\n", sids);
    printf("Templates:          %d\n\n", template_count);
}

static void cmd_analyze(const char *file_path, const char *sid) {
    if (!file_exists(file_path)) {
        printf("File not found: %s\n", file_path);
        return;
    }
    printf("\nAnalyzing %s...\n", file_path);
    code_snapshot_t *snap = analyze_file(file_path, sid ? sid : "default");
    if (snap) {
        sqlite3_stmt *stmt;
        const char *sql = "INSERT OR REPLACE INTO code_snapshots VALUES (?,?,?,?,?,?,?)";
        db_lock();
        if (sqlite3_prepare_v2(nil_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, snap->file_path, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, sid ? sid : "default", -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, snap->language, -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 4, snap->last_modified);
            sqlite3_bind_int(stmt, 5, snap->lines_of_code);
            sqlite3_bind_text(stmt, 6, snap->content_hash, -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 7, snap->embedding, sizeof(snap->embedding), SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        db_unlock();
        printf("  Language: %s\n", snap->language);
        printf("  Lines: %d\n", snap->lines_of_code);
        printf("  Hash: %.16s...\n\n", snap->content_hash);
        free(snap);
    }
}

static void cmd_index(const char *path, const char *sid) {
    printf("\nIndexing %s...\n", path);
    int count = index_directory(path, sid ? sid : "default");
    printf("\nIndexed %d files\n\n", count);
}

static void cmd_report(const char *sid) {
    printf("\nGenerating AI report for '%s'...\n", sid);
    char *report = generate_report(sid);
    if (report) {
        printf("\n%s\n\n", report);
        free(report);
    }
}

static void cmd_search(const char *query, const char *sid) {
    char *results = NULL;
    int found = nil_similar_code(query, sid ? sid : "default", &results);
    if (found > 0) {
        printf("\nSimilar code found:\n%s\n", results);
    } else {
        printf("\nNo similar code found.\n");
    }
    free(results);
}

static void cmd_parse_terminal(const char *file_path, const char *sid) {
    printf("\nParsing terminal output from %s...\n", file_path);
    int errors = nil_parse_terminal(file_path, sid ? sid : "default");
    if (errors >= 0) {
        printf("\nParsed %d errors\n\n", errors);
    }
}

static void cmd_resume(const char *sid) {
    printf("\nGenerating session resume for '%s'...\n", sid ? sid : "default");
    char *resume = nil_resume_session(sid ? sid : "default");
    if (resume) {
        printf("\nSID Resume String (%zu chars):\n", strlen(resume));
        printf("%s\n\n", resume);
        printf("Copy this string to your AI chat to resume the session.\n");
        printf("The AI will know:\n");
        printf("- All your assumptions and decisions\n");
        printf("- Recent terminal errors and their context\n");
        printf("- Current code state (files, hashes, languages)\n");
        printf("- Invariants to maintain (avoid repeating errors)\n\n");
        free(resume);
    }
}

static void cmd_import_sid(const char *sid_string, const char *sid) {
    printf("\nImporting SID string...\n");
    nil_import_sid(sid_string, sid ? sid : "default");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    nil_init_home();
    if (argc < 2) { cmd_help(); curl_global_cleanup(); return 0; }
    if (strcmp(argv[1], "init") != 0 && strcmp(argv[1], "help") != 0 &&
        strcmp(argv[1], "--help") != 0 && strcmp(argv[1], "-h") != 0) {
        if (nil_db_init() != 0) {
            fprintf(stderr, "Run 'nil init' first.\n");
            curl_global_cleanup();
            return 1;
        }
        load_all_templates();
    }
    if (strcmp(argv[1], "init") == 0) {
        cmd_init();
    }
    else if (strcmp(argv[1], "status") == 0) {
        cmd_status();
    }
    else if (strcmp(argv[1], "analyze") == 0 && argc > 2) {
        cmd_analyze(argv[2], argc > 3 ? argv[3] : NULL);
    }
    else if (strcmp(argv[1], "index") == 0 && argc > 2) {
        cmd_index(argv[2], argc > 3 ? argv[3] : NULL);
    }
    else if (strcmp(argv[1], "report") == 0 && argc > 2) {
        cmd_report(argv[2]);
    }
    else if (strcmp(argv[1], "search") == 0 && argc > 2) {
        char query[1024] = {0};
        for (int i = 2; i < argc; i++) { strcat(query, argv[i]); if (i < argc-1) strcat(query, " "); }
        cmd_search(query, argc > 3 ? argv[argc-1] : NULL);
    }
    else if (strcmp(argv[1], "watch") == 0 && argc > 2) {
        char path[NIL_MAX_PATH];
        if (argc > 3) {
            snprintf(path, sizeof(path), "%s", argv[3]);
        } else {
            snprintf(path, sizeof(path), "%s/sid/%s", nil_home, argv[2]);
            mkdir(path, 0755);
        }
        watch_session_t *session = nil_watch_start(argv[2], path);
        if (session) {
            printf("Press Enter to stop watching...\n");
            getchar();
            nil_watch_stop(session);
        }
    }
    else if (strcmp(argv[1], "parse") == 0 && argc > 2) {
        cmd_parse_terminal(argv[2], argc > 3 ? argv[3] : NULL);
    }
    else if (strcmp(argv[1], "resume") == 0) {
        cmd_resume(argc > 2 ? argv[2] : NULL);
    }
    else if (strcmp(argv[1], "import-sid") == 0 && argc > 2) {
        cmd_import_sid(argv[2], argc > 3 ? argv[3] : NULL);
    }
    else if (strcmp(argv[1], "template") == 0 && argc > 2 && strcmp(argv[2], "create") == 0) {
        create_default_templates();
        printf("Default templates created\n");
    }
    else {
        cmd_help();
    }
    for (int i = 0; i < template_count; i++) {
        if (templates[i].compiled) pcre2_code_free(templates[i].compiled);
    }
    free(templates);
    if (nil_db) {
        db_lock();
        sqlite3_close(nil_db);
        db_unlock();
    }
    curl_global_cleanup();
    return 0;
}

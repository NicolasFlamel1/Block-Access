// Header files
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// Structures

// Location configuration structure
typedef struct {
	
	// URL variables lengths
	ngx_array_t *urlVariablesLengths;
	
	// URL variables values
	ngx_array_t *urlVariablesValues;
	
	// Blocked address ranges
	ngx_array_t *blockedAddressRanges;
	
	// Unblocked locations
	ngx_array_t *unblockedLocations;
	
	// Allowed top-level domains
	ngx_array_t *allowedTopLevelDomains;
	
	// Allowed methods
	ngx_array_t *allowedMethods;
	
	// Required headers
	ngx_array_t *requiredHeaders;
	
} ngx_http_block_access_conf_t;

// Blocked address range structure
typedef struct {

	// Type
	sa_family_t type;
	
	// Start of range
	union {
		uint32_t ipv4StartOfRange;
		struct in6_addr ipv6StartOfRange;
	};
	
	// End of range
	union {
		uint32_t ipv4EndOfRange;
		struct in6_addr ipv6EndOfRange;
	};

} BlockedAddressRange;

// Required header structure
typedef struct {

	// Key
	ngx_str_t key;
	
	// Value
	ngx_regex_compile_t value;
	
	// Method
	ngx_uint_t method;

} RequiredHeader;

// Request context structure
typedef struct {

	// Done
	ngx_uint_t done;
	
	// Status
	ngx_uint_t status;
	
	// Request
	ngx_http_request_t *request;

} RequestContext;


// Function prototypes

// Block access setup
static char *blockAccessSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Block setup
static char *blockSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Unblock setup
static char *unblockSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Allow top-level domain setup
static char *allowTopLevelDomainSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Allow method setup
static char *allowMethodSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Require header setup
static char *requireHeaderSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data);

// Postconfiguration
static ngx_int_t postconfiguration(ngx_conf_t *configuration);

// Create location configuration
static void *createLocationConfiguration(ngx_conf_t *configuration);

// Merge location configuration
static char *mergeLocationConfiguration(ngx_conf_t *configuration, void *parent, void *child);

// Access handler
static ngx_int_t accessHandler(ngx_http_request_t *request);

// Resolve handler
static void resolveHandler(ngx_resolver_ctx_t *context);

// Block IPv4 result
static ngx_uint_t blockIpv4Result(const ngx_array_t *blockedAddressRanges, const struct sockaddr_in *address);

// Block IPv6 result
static ngx_uint_t blockIpv6Result(const ngx_array_t *blockedAddressRanges, const struct sockaddr_in6 *address);


// Constants

// Directives
static ngx_command_t directives[] = {

	// Block access
	{
	
		// Name
		ngx_string("block_access"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		
		// Setup
		blockAccessSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Offset
		offsetof(ngx_http_block_access_conf_t, urlVariablesLengths),
		
		// Reserved
		NULL
	},
	
	// Block
	{
	
		// Name
		ngx_string("block"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
		
		// Setup
		blockSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Index
		offsetof(ngx_http_block_access_conf_t, blockedAddressRanges),
		
		// Reserved
		NULL
	},
	
	// Unblock
	{
	
		// Name
		ngx_string("unblock"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		
		// Setup
		unblockSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Index
		offsetof(ngx_http_block_access_conf_t, unblockedLocations),
		
		// Reserved
		NULL
	},
	
	// Allow top-level domain
	{
	
		// Name
		ngx_string("allow_top_level_domain"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		
		// Setup
		allowTopLevelDomainSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Index
		offsetof(ngx_http_block_access_conf_t, allowedTopLevelDomains),
		
		// Reserved
		NULL
	},
	
	// Allow method
	{
	
		// Name
		ngx_string("allow_method"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		
		// Setup
		allowMethodSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Index
		offsetof(ngx_http_block_access_conf_t, allowedMethods),
		
		// Reserved
		NULL
	},
	
	// Require header
	{
	
		// Name
		ngx_string("require_header"),
		
		// Type
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23,
		
		// Setup
		requireHeaderSetup,
		
		// Configuration
		NGX_HTTP_LOC_CONF_OFFSET,
		
		// Index
		offsetof(ngx_http_block_access_conf_t, requiredHeaders),
		
		// Reserved
		NULL
	},
	
	// End of directives
	ngx_null_command
};

// Context
static ngx_http_module_t context = {

	// Preconfiguration
	NULL,
	
	// Postconfiguration
	postconfiguration,
	
	// Create main configuration
	NULL,
	
	// Initialize main configuration
	NULL,
	
	// Create server configuration
	NULL,
	
	// Merge server configuration
	NULL,
	
	// Create location configuration
	createLocationConfiguration,
	
	// Merge location configuration
	mergeLocationConfiguration
};

// Module
ngx_module_t ngx_http_block_access_module = {

	// Version header
	NGX_MODULE_V1,
	
	// Context
	&context,
	
	// Directives
	directives,
	
	// Type
	NGX_HTTP_MODULE,
	
	// initialize master
	NULL,
	
	// Initialize module
	NULL,
	
	// Initialize process
	NULL,
	
	// Initialize thread
	NULL,
	
	// Exit thread
	NULL,
	
	// Exit process
	NULL,
	
	// Exit master
	NULL,
	
	// Version footer
	NGX_MODULE_V1_PADDING
};


// Supporting function implementation

// Block access setup
char *blockAccessSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	ngx_str_t *arguments = configuration->args->elts;
	
	// Get URL
	ngx_str_t *url = &arguments[1];
	
	// Create script compile
	ngx_http_script_compile_t scriptCompile;
	ngx_memzero(&scriptCompile, sizeof(ngx_http_script_compile_t));
	scriptCompile.cf = configuration;
	scriptCompile.source = url;
	scriptCompile.lengths = &locationConfiguration->urlVariablesLengths;
	scriptCompile.values = &locationConfiguration->urlVariablesValues;
	scriptCompile.variables = ngx_http_script_variables_count(url);
	scriptCompile.complete_lengths = 1;
	scriptCompile.complete_values = 1;
	
	// Check if compiling script compile failed
	if(ngx_http_script_compile(&scriptCompile) != NGX_OK) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Return configuration ok
	return NGX_CONF_OK;
}

// Block setup
char *blockSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	const ngx_str_t *arguments = configuration->args->elts;
	
	// Get start of range
	const ngx_str_t *startOfRange = &arguments[1];
	
	// Get end of range
	const ngx_str_t *endOfRange = (configuration->args->nelts == 3) ? &arguments[2] : NULL;
	
	// Get blocked address ranges
	ngx_array_t **blockedAddressRanges = (ngx_array_t **)((char *)locationConfiguration + command->offset);
	
	// Check if blocked address ranges doesn't exist
	if(!*blockedAddressRanges) {
	
		// Check if creating blocked address ranges failed
		*blockedAddressRanges = ngx_array_create(configuration->pool, 1, sizeof(BlockedAddressRange));
		if(!*blockedAddressRanges) {
		
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Check if adding value to blocked address ranges failed
	BlockedAddressRange *blockedAddressRange = ngx_array_push(*blockedAddressRanges);
	if(!blockedAddressRange) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Get start of range as a string
	char startOfRangeBuffer[startOfRange->len + sizeof((char)'\0')];
	ngx_memcpy(startOfRangeBuffer, startOfRange->data, startOfRange->len);
	startOfRangeBuffer[sizeof(startOfRangeBuffer) - sizeof((char)'\0')] = '\0';
	
	// Check if start of range is an IPv4 address
	struct sockaddr_in ipv4Address;
	if(inet_pton(AF_INET, startOfRangeBuffer, &ipv4Address.sin_addr)) {
	
		// Set blocked address range type and start or range
		blockedAddressRange->type = AF_INET;
		blockedAddressRange->ipv4StartOfRange = ntohl(ipv4Address.sin_addr.s_addr);
		
		// Check if end of range is provided
		if(endOfRange) {
		
			// Get end of range as a string
			char endOfRangeBuffer[endOfRange->len + sizeof((char)'\0')];
			ngx_memcpy(endOfRangeBuffer, endOfRange->data, endOfRange->len);
			endOfRangeBuffer[sizeof(endOfRangeBuffer) - sizeof((char)'\0')] = '\0';
			
			// Check if end of range is an IPv4 address
			if(inet_pton(AF_INET, endOfRangeBuffer, &ipv4Address.sin_addr)) {
			
				// Set blocked address range end of range
				blockedAddressRange->ipv4EndOfRange = ntohl(ipv4Address.sin_addr.s_addr);
				
				// Check if blocked address range is invalid
				if(blockedAddressRange->ipv4StartOfRange > blockedAddressRange->ipv4EndOfRange) {
			
					// Log error
					ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", endOfRange);
					
					// Return configuration error
					return NGX_CONF_ERROR;
				}
			}
			
			// Otherwise
			else {
			
				// Log error
				ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", endOfRange);
				
				// Return configuration error
				return NGX_CONF_ERROR;
			}
		}
		
		// Otherwise
		else {
		
			// Set blocked address range to contain only the starting address
			blockedAddressRange->ipv4EndOfRange = blockedAddressRange->ipv4StartOfRange;
		}
	}
	
	// Otherwise
	else {
	
		// Check if start of range is an IPv4 address
		struct sockaddr_in6 ipv6Address;
		if(inet_pton(AF_INET6, startOfRangeBuffer, &ipv6Address.sin6_addr)) {
		
			// Set blocked address range
			blockedAddressRange->type = AF_INET6;
			memcpy(&blockedAddressRange->ipv6StartOfRange, &ipv6Address.sin6_addr, sizeof(struct in6_addr));
			
			// Check if end of range is provided
			if(endOfRange) {
			
				// Get end of range as a string
				char endOfRangeBuffer[endOfRange->len + sizeof((char)'\0')];
				ngx_memcpy(endOfRangeBuffer, endOfRange->data, endOfRange->len);
				endOfRangeBuffer[sizeof(endOfRangeBuffer) - sizeof((char)'\0')] = '\0';
				
				// Check if end of range is an IPv6 address
				if(inet_pton(AF_INET6, endOfRangeBuffer, &ipv6Address.sin6_addr)) {
				
					// Set blocked address range end of range
					memcpy(&blockedAddressRange->ipv6EndOfRange, &ipv6Address.sin6_addr, sizeof(struct in6_addr));
					
					// Check if blocked address range is invalid
					if(memcmp(&blockedAddressRange->ipv6StartOfRange, &blockedAddressRange->ipv6EndOfRange, sizeof(struct in6_addr)) > 0) {
				
						// Log error
						ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", endOfRange);
						
						// Return configuration error
						return NGX_CONF_ERROR;
					}
				}
				
				// Otherwise
				else {
				
					// Log error
					ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", endOfRange);
					
					// Return configuration error
					return NGX_CONF_ERROR;
				}
			}
			
			// Otherwise
			else {
			
				// Set blocked address range to contain only the starting address
				memcpy(&blockedAddressRange->ipv6EndOfRange, &blockedAddressRange->ipv6StartOfRange, sizeof(struct in6_addr));
			}
		}
		
		// Otherwise
		else {
	
			// Log error
			ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", startOfRange);
			
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Return configuration ok
	return NGX_CONF_OK;
}

// Unblock setup
char *unblockSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	ngx_str_t *arguments = configuration->args->elts;
	
	// Get location
	ngx_str_t *location = &arguments[1];
	
	// Check if case insensitive is provided
	const ngx_uint_t caseInsensitive = location->len && location->data[0] == '~';
	
	// Get unblocked locations
	ngx_array_t **unblockedLocations = (ngx_array_t **)((char *)locationConfiguration + command->offset);
	
	// Check if unblocked locations doesn't exist
	if(!*unblockedLocations) {
	
		// Check if creating unblocked locations failed
		*unblockedLocations = ngx_array_create(configuration->pool, 1, sizeof(ngx_regex_compile_t));
		if(!*unblockedLocations) {
		
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Check if adding value to unblocked locations failed
	ngx_regex_compile_t *unblockedLocation = ngx_array_push(*unblockedLocations);
	if(!unblockedLocation) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Check if case insensitive
	if(caseInsensitive) {
	
		// Remove case insensitive character from location
		--location->len;
		++location->data;
	}
	
	// Check if location is invalid
	if(!location->len) {
	
		// Check if case insensitive
		if(caseInsensitive) {
		
			// Add case insensitive character to location
			++location->len;
			--location->data;
		}
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", location);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Initialize unblocked location
	ngx_memzero(unblockedLocation, sizeof(ngx_regex_compile_t));
	unblockedLocation->pattern = *location;
	unblockedLocation->pool = configuration->pool;
	unblockedLocation->options = caseInsensitive ? NGX_REGEX_CASELESS : 0;
	
	u_char errstr[NGX_MAX_CONF_ERRSTR];
	unblockedLocation->err.len = sizeof(errstr);
	unblockedLocation->err.data = errstr;
	
	// Check if compiling unblocked location failed or the unblocked location contains captures
	if(ngx_regex_compile(unblockedLocation) != NGX_OK || unblockedLocation->captures) {
	
		// Check if case insensitive
		if(caseInsensitive) {
		
			// Add case insensitive character to location
			++location->len;
			--location->data;
		}
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", location);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Return configuration ok
	return NGX_CONF_OK;
}

// Allow top level domain setup
char *allowTopLevelDomainSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	const ngx_str_t *arguments = configuration->args->elts;
	
	// Get top-level domain
	const ngx_str_t *topLevelDomain = &arguments[1];
	
	// Get allowed top-level domains
	ngx_array_t **allowedTopLevelDomains = (ngx_array_t **)((char *)locationConfiguration + command->offset);
	
	// Check if allowed top-level domains doesn't exist
	if(!*allowedTopLevelDomains) {
	
		// Check if creating allowed top-level domains failed
		*allowedTopLevelDomains = ngx_array_create(configuration->pool, 1, sizeof(ngx_str_t));
		if(!*allowedTopLevelDomains) {
		
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Check if adding value to allowed top-level domains failed
	ngx_str_t *allowedTopLevelDomain = ngx_array_push(*allowedTopLevelDomains);
	if(!allowedTopLevelDomain) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Set allowed top-level domain
	*allowedTopLevelDomain = *topLevelDomain;
	
	// Check if top-level domain is invalid
	if(topLevelDomain->len < 3 || topLevelDomain->len > 64 || topLevelDomain->data[0] != '.' || topLevelDomain->data[1] == '-' || topLevelDomain->data[topLevelDomain->len - sizeof((char)'\0')] == '-') {
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", topLevelDomain);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Go through all characters in the top-level domain
	for(size_t i = sizeof((char)'.'); i < topLevelDomain->len; ++i) {
	
		// Check if character isn't alphanumeric or a hyphen
		if(!isalnum(topLevelDomain->data[i]) && topLevelDomain->data[i] != '-') {
		
			// Log error
			ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", topLevelDomain);
			
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}

	// Return configuration ok
	return NGX_CONF_OK;
}

// Allow method setup
char *allowMethodSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	const ngx_str_t *arguments = configuration->args->elts;
	
	// Get method
	const ngx_str_t *method = &arguments[1];
	
	// Get allowed methods
	ngx_array_t **allowedMethods = (ngx_array_t **)((char *)locationConfiguration + command->offset);
	
	// Check if allowed methods doesn't exist
	if(!*allowedMethods) {
	
		// Check if creating allowed methods failed
		*allowedMethods = ngx_array_create(configuration->pool, 1, sizeof(ngx_uint_t));
		if(!*allowedMethods) {
		
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Check if adding value to allowed methods failed
	ngx_uint_t *allowedMethod = ngx_array_push(*allowedMethods);
	if(!allowedMethod) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Check if method is GET
	if(method->len == sizeof("GET") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"GET", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_GET;
	}
	
	// Otherwise check if method is HEAD
	else if(method->len == sizeof("HEAD") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"HEAD", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_HEAD;
	}
	
	// Otherwise check if method is POST
	else if(method->len == sizeof("POST") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"POST", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_POST;
	}
	
	// Otherwise check if method is PUT
	else if(method->len == sizeof("PUT") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"PUT", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_PUT;
	}
	
	// Otherwise check if method is DELETE
	else if(method->len == sizeof("DELETE") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"DELETE", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_DELETE;
	}
	
	// Otherwise check if method is OPTIONS
	else if(method->len == sizeof("OPTIONS") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"OPTIONS", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_OPTIONS;
	}
	
	// Otherwise check if method is TRACE
	else if(method->len == sizeof("TRACE") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"TRACE", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_TRACE;
	}
	
	// Otherwise check if method is PATCH
	else if(method->len == sizeof("PATCH") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"PATCH", method->len)) {
	
		// Set allowed method
		*allowedMethod = NGX_HTTP_PATCH;
	}
	
	// Otherwise
	else {
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", method);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}

	// Return configuration ok
	return NGX_CONF_OK;
}

// Require header setup
char *requireHeaderSetup(ngx_conf_t *configuration, ngx_command_t *command, void *data) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = data;
	
	// Get arguments
	ngx_str_t *arguments = configuration->args->elts;
	
	// Get key
	const ngx_str_t *key = &arguments[1];
	
	// Get value
	ngx_str_t *value = &arguments[2];
	
	// Check if case insensitive is provided
	const ngx_uint_t caseInsensitive = value->len && value->data[0] == '~';
	
	// Get method
	const ngx_str_t *method = (configuration->args->nelts == 4) ? &arguments[3] : NULL;
	
	// Get required headers
	ngx_array_t **requiredHeaders = (ngx_array_t **)((char *)locationConfiguration + command->offset);
	
	// Check if required headers doesn't exist
	if(!*requiredHeaders) {
	
		// Check if creating required headers failed
		*requiredHeaders = ngx_array_create(configuration->pool, 1, sizeof(RequiredHeader));
		if(!*requiredHeaders) {
		
			// Return configuration error
			return NGX_CONF_ERROR;
		}
	}
	
	// Check if adding value to required headers failed
	RequiredHeader *requiredHeader = ngx_array_push(*requiredHeaders);
	if(!requiredHeader) {
	
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Check if key is invalid
	if(!key->len) {
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", key);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Set required header's key
	requiredHeader->key = *key;
	
	// Check if case insensitive
	if(caseInsensitive) {
	
		// Remove case insensitive character from value
		--value->len;
		++value->data;
	}
	
	// Check if value is invalid
	if(!value->len) {
	
		// Check if case insensitive
		if(caseInsensitive) {
		
			// Add case insensitive character to value
			++value->len;
			--value->data;
		}
		
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", value);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Initialize required header's value
	ngx_memzero(&requiredHeader->value, sizeof(ngx_regex_compile_t));
	requiredHeader->value.pattern = *value;
	requiredHeader->value.pool = configuration->pool;
	requiredHeader->value.options = caseInsensitive ? NGX_REGEX_CASELESS : 0;
	
	u_char errstr[NGX_MAX_CONF_ERRSTR];
	requiredHeader->value.err.len = sizeof(errstr);
	requiredHeader->value.err.data = errstr;
	
	// Check if compiling required header's value failed or the required header's value contains captures
	if(ngx_regex_compile(&requiredHeader->value) != NGX_OK || requiredHeader->value.captures) {
	
		// Check if case insensitive
		if(caseInsensitive) {
		
			// Add case insensitive character to value
			++value->len;
			--value->data;
		}
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", value);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Check if method isn't provided
	if(!method) {
	
		// Set required header's method
		requiredHeader->method = UINTMAX_MAX;
	}
	
	// Otherwise check if method is GET
	else if(method->len == sizeof("GET") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"GET", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_GET;
	}
	
	// Otherwise check if method is HEAD
	else if(method->len == sizeof("HEAD") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"HEAD", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_HEAD;
	}
	
	// Otherwise check if method is POST
	else if(method->len == sizeof("POST") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"POST", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_POST;
	}
	
	// Otherwise check if method is PUT
	else if(method->len == sizeof("PUT") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"PUT", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_PUT;
	}
	
	// Otherwise check if method is DELETE
	else if(method->len == sizeof("DELETE") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"DELETE", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_DELETE;
	}
	
	// Otherwise check if method is OPTIONS
	else if(method->len == sizeof("OPTIONS") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"OPTIONS", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_OPTIONS;
	}
	
	// Otherwise check if method is TRACE
	else if(method->len == sizeof("TRACE") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"TRACE", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_TRACE;
	}
	
	// Otherwise check if method is PATCH
	else if(method->len == sizeof("PATCH") - sizeof((char)'\0') && !ngx_strncasecmp(method->data, (u_char *)"PATCH", method->len)) {
	
		// Set required header's method
		requiredHeader->method = NGX_HTTP_PATCH;
	}
	
	// Otherwise
	else {
	
		// Log error
		ngx_conf_log_error(NGX_LOG_EMERG, configuration, 0, "invalid parameter \"%V\"", method);
		
		// Return configuration error
		return NGX_CONF_ERROR;
	}
	
	// Return configuration ok
	return NGX_CONF_OK;
}

// Postconfiguration
ngx_int_t postconfiguration(ngx_conf_t *configuration) {

	// Get core configuration
	ngx_http_core_main_conf_t *coreConfiguration = ngx_http_conf_get_module_main_conf(configuration, ngx_http_core_module);
	
	// Check if adding handler to HTTP access phase handler failed
	ngx_http_handler_pt *handler = ngx_array_push(&coreConfiguration->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if(!handler) {
	
		// Return error
		return NGX_ERROR;
	}
	
	// Set handler to access handler
	*handler = accessHandler;
	
	// Return ok
	return NGX_OK;
}

// Create location configuration
void *createLocationConfiguration(ngx_conf_t *configuration) {

	// Check if creating location configuration failed
	ngx_http_block_access_conf_t *locationConfiguration = ngx_pcalloc(configuration->pool, sizeof(ngx_http_block_access_conf_t));
	if(!locationConfiguration) {
	
		// Return null
		return NULL;
	}
	
	// Return location configuration
	return locationConfiguration;
}

// Merge location configuration
char *mergeLocationConfiguration(ngx_conf_t *configuration, void *parent, void *child) {

	// Initialize current and previous location configuration
	ngx_http_block_access_conf_t *currentLocationConfiguration = child;
	const ngx_http_block_access_conf_t *previousLocationConfiguration = parent;
	
	// Merge location configuration values
	ngx_conf_merge_ptr_value(currentLocationConfiguration->urlVariablesLengths, previousLocationConfiguration->urlVariablesLengths, NULL);
	ngx_conf_merge_ptr_value(currentLocationConfiguration->urlVariablesValues, previousLocationConfiguration->urlVariablesValues, NULL);
	ngx_conf_merge_ptr_value(currentLocationConfiguration->unblockedLocations, previousLocationConfiguration->unblockedLocations, NULL);
	
	if(!currentLocationConfiguration->blockedAddressRanges) {
		currentLocationConfiguration->blockedAddressRanges = previousLocationConfiguration->blockedAddressRanges;
	}
	
	if(!currentLocationConfiguration->allowedTopLevelDomains) {
		currentLocationConfiguration->allowedTopLevelDomains = previousLocationConfiguration->allowedTopLevelDomains;
	}
	
	if(!currentLocationConfiguration->allowedMethods) {
		currentLocationConfiguration->allowedMethods = previousLocationConfiguration->allowedMethods;
	}
	
	if(!currentLocationConfiguration->requiredHeaders) {
		currentLocationConfiguration->requiredHeaders = previousLocationConfiguration->requiredHeaders;
	}
	
	// Return configuration ok
	return NGX_CONF_OK;
}

// Access handler
ngx_int_t accessHandler(ngx_http_request_t *request) {

	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = ngx_http_get_module_loc_conf(request, ngx_http_block_access_module);
	
	// Check if module isn't used
	if(!locationConfiguration->urlVariablesLengths) {
	
		// Return declined
		return NGX_DECLINED;
	}
	
	// Check if getting request context was successful
	RequestContext *requestContext = ngx_http_get_module_ctx(request, ngx_http_block_access_module);
	if(requestContext) {
	
		// Check if request isn't done
		if(!requestContext->done) {
		
			// Return again
			return NGX_AGAIN;
		}
		
		// Check request's status
		switch(requestContext->status) {
		
			// Ok
			case NGX_HTTP_OK:
			
				// Return ok
				return NGX_OK;
		
			// Forbidden
			case NGX_HTTP_FORBIDDEN:
			
				// Return request's status
				return requestContext->status;
			
			// Default
			default:
			
				// Return internal server error
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	
	// Check if creating request context failed
	requestContext = ngx_pcalloc(request->pool, sizeof(RequestContext));
	if(!requestContext) {
	
		// Return error
		return NGX_ERROR;
	}
	
	// Set request context
	ngx_http_set_ctx(request, requestContext, ngx_http_block_access_module);
	
	// Set request context's request
	requestContext->request = request;
	
	// Check if running script failed
	ngx_str_t result;
	if(!ngx_http_script_run(request, &result, locationConfiguration->urlVariablesLengths->elts, 0, locationConfiguration->urlVariablesValues->elts)) {
	
		// Return error
		return NGX_ERROR;
	}
	
	// Check if request is using HTTP
	size_t offset;
	u_short port;
	if(result.len >= sizeof("http://") - sizeof((char)'\0') && !ngx_strncasecmp(result.data, (u_char *)"http://", sizeof("http://") - sizeof((char)'\0'))) {
	
		// Set offset and port
		offset = sizeof("http://") - sizeof((char)'\0');
		port = 80;
	}
	
	// Otherwise check if request is using HTTPS
	else if(result.len >= sizeof("https://") - sizeof((char)'\0') && !ngx_strncasecmp(result.data, (u_char *)"https://", sizeof("https://") - sizeof((char)'\0'))) {
	
		// Set offset and port
		offset = sizeof("https://") - sizeof((char)'\0');
		port = 443;
	}
	
	// Otherwise
	else {
	
		// Log info
		ngx_log_error(NGX_LOG_INFO, request->connection->log, 0, "blocked access to non HTTP or HTTPS resource");
	
		// Return forbidden
		return NGX_HTTP_FORBIDDEN;
	}
	
	// Create URL
	ngx_url_t url;
	ngx_memzero(&url, sizeof(ngx_url_t));
	url.url.len = result.len - offset;
	url.url.data = result.data + offset;
	url.default_port = port;
	url.uri_part = 1;
	url.no_resolve = 1;
	
	// Check if parsing URL failed
	if(ngx_parse_url(request->pool, &url) != NGX_OK) {
	
		// Log info
		ngx_log_error(NGX_LOG_INFO, request->connection->log, 0, "blocked access to invalid resource location");
	
		// Return forbidden
		return NGX_HTTP_FORBIDDEN;
	}
	
	// Check if URL isn't using IP to communicate
	if(url.family != AF_INET && url.family != AF_INET6) {
	
		// Log info
		ngx_log_error(NGX_LOG_INFO, request->connection->log, 0, "blocked access to non HTTP or HTTPS resource");
	
		// Return forbidden
		return NGX_HTTP_FORBIDDEN;
	}
	
	// Check if allowed methods exist
	if(locationConfiguration->allowedMethods) {
	
		// Go through all allowed methods
		ngx_uint_t blockedMethod = 1;
		const ngx_uint_t *allowedMethods = locationConfiguration->allowedMethods->elts;
		for(ngx_uint_t i = 0; i < locationConfiguration->allowedMethods->nelts; ++i) {
		
			// Get allowed method
			const ngx_uint_t *allowedMethod = &allowedMethods[i];
			
			// Check if method is allowed
			if(request->method == *allowedMethod) {
				
				// Clear blocked method
				blockedMethod = 0;
				
				// Break
				break;
			}
		}
		
		// Check if using a method that isn't allowed
		if(blockedMethod) {
		
			// Log info
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "blocked access to %V", &url.uri);
		
			// Return forbidden
			return NGX_HTTP_FORBIDDEN;
		}
	}
	
	// Check if allowed top-level domains exist
	if(locationConfiguration->allowedTopLevelDomains) {
	
		// Go through all allowed top-level domains
		ngx_uint_t blockedTopLevelDomain = 1;
		const ngx_str_t *allowedTopLevelDomains = locationConfiguration->allowedTopLevelDomains->elts;
		for(ngx_uint_t i = 0; i < locationConfiguration->allowedTopLevelDomains->nelts; ++i) {
		
			// Get allowed top-level domain
			const ngx_str_t *allowedTopLevelDomain = &allowedTopLevelDomains[i];
			
			// Check if top-level domain is allowed
			if(url.host.len >= allowedTopLevelDomain->len && !ngx_strncasecmp(&url.host.data[url.host.len - allowedTopLevelDomain->len], allowedTopLevelDomain->data, allowedTopLevelDomain->len)) {
				
				// Clear blocked top-level domain
				blockedTopLevelDomain = 0;
				
				// Break
				break;
			}
		}
		
		// Check if accessing a top-level domain that isn't allowed
		if(blockedTopLevelDomain) {
		
			// Log info
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "blocked access to %V", &url.uri);
		
			// Return forbidden
			return NGX_HTTP_FORBIDDEN;
		}
	}
	
	// Check if unblocked locations exist
	if(locationConfiguration->unblockedLocations) {
	
		// Go through all unblocked locations
		ngx_uint_t blockedLocation = 1;
		const ngx_regex_compile_t *unblockedLocations = locationConfiguration->unblockedLocations->elts;
		for(ngx_uint_t i = 0; i < locationConfiguration->unblockedLocations->nelts; ++i) {
		
			// Get unblocked location
			const ngx_regex_compile_t *unblockedLocation = &unblockedLocations[i];
			
			// Check if location isn't blocked
			if(ngx_regex_exec(unblockedLocation->regex, &url.uri, NULL, 0) >= 0) {
			
				// Clear blocked location
				blockedLocation = 0;
				
				// Break
				break;
			}
		}
		
		// Check if accessing a blocked location
		if(blockedLocation) {
		
			// Log info
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "blocked access to %V", &url.uri);
		
			// Return forbidden
			return NGX_HTTP_FORBIDDEN;
		}
	}
	
	// Check if required headers exists
	if(locationConfiguration->requiredHeaders) {
	
		// Go through all required headers
		ngx_uint_t invalidHeaders = 0;
		const RequiredHeader *requiredHeaders = locationConfiguration->requiredHeaders->elts;
		for(ngx_uint_t i = 0; i < locationConfiguration->requiredHeaders->nelts; ++i) {
		
			// Get required header
			const RequiredHeader *requiredHeader = &requiredHeaders[i];
			
			// Check if requried header's method is applicable to the current request
			if(requiredHeader->method & request->method) {
			
				// Go through all headers
				ngx_uint_t headerFound = 0;
				const ngx_list_part_t *part = &request->headers_in.headers.part;
				ngx_table_elt_t *header = part->elts;
				for(ngx_uint_t j = 0;; ++j) {
				
					// Check if at the end of the part
					if(j >= part->nelts) {
					
						// Check if at last part
						if(!part->next) {
						
							// Break
							break;
						}
						
						// Go to next part
						part = part->next;
						header = part->elts;
						j = 0;
					}
					
					// Check if header is invaid
					if(!header[j].hash) {
					
						// Continue
						continue;
					}
					
					// Check if header is for the required header
					if(header[j].key.len == requiredHeader->key.len && !ngx_strncasecmp(header[j].key.data, requiredHeader->key.data, requiredHeader->key.len)) {
					
						// Set header found
						headerFound = 1;
						
						// Check if header's value isn't the required value
						if(ngx_regex_exec(requiredHeader->value.regex, &header[j].value, NULL, 0) < 0) {
					
							// Go through all other required headers
							ngx_uint_t validHeader = 0;
							for(ngx_uint_t k = 0; k < locationConfiguration->requiredHeaders->nelts; ++k) {
							
								// Check if required header isn't the same
								if(k != i) {
							
									// Get other required header
									const RequiredHeader *otherRequiredHeader = &requiredHeaders[k];
									
									// Check if other requried header's method is applicable to the current request
									if(otherRequiredHeader->method & request->method) {
									
										// Check if header is for the other required header
										if(header[j].key.len == otherRequiredHeader->key.len && !ngx_strncasecmp(header[j].key.data, otherRequiredHeader->key.data, otherRequiredHeader->key.len)) {
										
											// Check if header's value is the other required value
											if(ngx_regex_exec(otherRequiredHeader->value.regex, &header[j].value, NULL, 0) >= 0) {
											
												// Set valid header
												validHeader = 1;
												
												// Break
												break;
											}
										}
									}
								}
							}
							
							// Check if header isn't valid
							if(!validHeader) {
							
								// Set invalid headers
								invalidHeaders = 1;
							
								// Break
								break;
							}
						}
					}
				}
				
				// Check if required header doesn't exist
				if(!headerFound) {
				
					// Set invalid headers
					invalidHeaders = 1;
				}
				
				// Check if headers are invalid
				if(invalidHeaders) {
				
					// Break
					break;
				}
			}
		}
		
		// Check if headers are invalid
		if(invalidHeaders) {
		
			// Log info
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "blocked access to %V", &url.uri);
		
			// Return forbidden
			return NGX_HTTP_FORBIDDEN;
		}
	}
	
	// Check if blocked address ranges exist
	if(locationConfiguration->blockedAddressRanges) {
	
		// Get core configuration
		const ngx_http_core_loc_conf_t *coreConfiguration = ngx_http_get_module_loc_conf(request, ngx_http_core_module);
		
		// Check if getting resolver context failed
		ngx_resolver_ctx_t *resolverContext = ngx_resolve_start(coreConfiguration->resolver, NULL);
		if(!resolverContext) {
		
			// Return error
			return NGX_ERROR;
		}
		
		// Check if resolver isn't set
		if(resolverContext == NGX_NO_RESOLVER) {
		
			// Log error
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "no resolver defined to resolve %V", &url.host);
		
			// Return error
			return NGX_ERROR;
		}
		
		// Check if resolving name failed
		resolverContext->name = url.host;
		resolverContext->handler = resolveHandler;
		resolverContext->data = requestContext;
		resolverContext->timeout = coreConfiguration->resolver_timeout;
		
		if(ngx_resolve_name(resolverContext) != NGX_OK) {
		
			// Return error
			return NGX_ERROR;
		}
		
		// Return again
		return NGX_AGAIN;
	}
	
	// Otherwise
	else
	
		// Return ok
		return NGX_OK;
}

// Resolve handler
void resolveHandler(ngx_resolver_ctx_t *context) {

	// Get request context
	RequestContext *requestContext = context->data;
	
	// Get request
	ngx_http_request_t *request = requestContext->request;
	
	// Get location configuration
	const ngx_http_block_access_conf_t *locationConfiguration = ngx_http_get_module_loc_conf(request, ngx_http_block_access_module);
	
	// Set status to ok
	requestContext->status = NGX_HTTP_OK;
	
	// Check if name couldn't be resolved
	if(context->state) {
	
		// Get name as a string
		char buffer[context->name.len + sizeof((char)'\0')];
		ngx_memcpy(buffer, context->name.data, context->name.len);
		buffer[sizeof(buffer) - sizeof((char)'\0')] = '\0';
		
		// Check if name is an IPv4 address
		struct sockaddr_in ipv4Address;
		if(inet_pton(AF_INET, buffer, &ipv4Address.sin_addr)) {
		
			// Set status to block IPv4 result
			requestContext->status = blockIpv4Result(locationConfiguration->blockedAddressRanges, &ipv4Address);
		}
		
		// Otherwise
		else {
		
			// Check if name is formatted like an IPv6 address
			if(sizeof(buffer) >= sizeof((char)'[') + sizeof((char)']') && buffer[0] == '[' && buffer[sizeof(buffer) - sizeof((char)'\0') - sizeof((char)']')] == ']') {
			
				// Get IPv6 part of name
				ngx_memmove(buffer, &buffer[sizeof((char)'[')], sizeof(buffer) - sizeof((char)'\0') - sizeof((char)']'));
				buffer[sizeof(buffer) - sizeof((char)'\0') - sizeof((char)']') - sizeof((char)'[')] = '\0';
			
				// Check if name is an IPv6 address
				struct sockaddr_in6 ipv6Address;
				if(inet_pton(AF_INET6, buffer, &ipv6Address.sin6_addr)) {
				
					// Set status to block IPv6 result
					requestContext->status = blockIpv6Result(locationConfiguration->blockedAddressRanges, &ipv6Address);
				}
				
				// Otherwise
				else {
				
					// Set status to forbidden
					requestContext->status = NGX_HTTP_FORBIDDEN;
				}
			}
			
			// Otherwise
			else {
			
				// Set status to forbidden
				requestContext->status = NGX_HTTP_FORBIDDEN;
			}
		}
	}
	
	// Otherwise check if no addresses exist
	else if(!context->naddrs || !context->addrs) {
	
		// Set status to forbidden
		requestContext->status = NGX_HTTP_FORBIDDEN;
	}
	
	// Otherwise
	else {
	
		// Go through all resolved addresses
		for(ngx_uint_t i = 0; i < context->naddrs; ++i) {
		
			// Check address type
			switch(context->addrs[i].sockaddr->sa_family) {
			
				// IPv4
				case AF_INET:
				
					{
						// Get address
						const struct sockaddr_in *ipv4Address = (struct sockaddr_in *)context->addrs[i].sockaddr;
					
						// Set status to block IPv4 result
						requestContext->status = blockIpv4Result(locationConfiguration->blockedAddressRanges, ipv4Address);
					}
				
					// Break
					break;
				
				// IPv6
				case AF_INET6:
				
					{
						// Get address
						const struct sockaddr_in6 *ipv6Address = (struct sockaddr_in6 *)context->addrs[i].sockaddr;
					
						// Set status to block IPv6 result
						requestContext->status = blockIpv6Result(locationConfiguration->blockedAddressRanges, ipv6Address);
					}
				
					// Break
					break;
				
				// Default
				default:
				
					// Set status to forbidden
					requestContext->status = NGX_HTTP_FORBIDDEN;
					
					// Break
					break;
			}
			
			// Check if status was set
			if(requestContext->status != NGX_HTTP_OK) {
			
				// Break
				break;
			}
		}
	}
	
	// Check if access was blocked
	if(requestContext->status == NGX_HTTP_FORBIDDEN) {
	
		// Log info
		ngx_log_error(NGX_LOG_INFO, request->connection->log, 0, "blocked access to %V", &context->name);
	}
	
	// Resolve name done
	ngx_resolve_name_done(context);
	
	// Set done
	requestContext->done = 1;
	
	// Run phases
	ngx_http_core_run_phases(request);
}

// Block IPv4 result
ngx_uint_t blockIpv4Result(const ngx_array_t *blockedAddressRanges, const struct sockaddr_in *address) {

	// Check if blocked address ranges exist
	if(blockedAddressRanges) {
	
		// Get address in host byte order
		const uint32_t addressHostByteOrder = ntohl(address->sin_addr.s_addr);
	
		// Go through all blocked address ranges
		const BlockedAddressRange *blockedAddressRangesValues = blockedAddressRanges->elts;
		for(ngx_uint_t i = 0; i < blockedAddressRanges->nelts; ++i) {
		
			// Get blocked address range
			const BlockedAddressRange *blockedAddressRange = &blockedAddressRangesValues[i];
			
			// Check if blocked address range is for IPv4 addresses
			if(blockedAddressRange->type == AF_INET) {
			
				// Check if address is in the blocked address range
				if(addressHostByteOrder >= blockedAddressRange->ipv4StartOfRange && addressHostByteOrder <= blockedAddressRange->ipv4EndOfRange) {
				
					// Return forbidden
					return NGX_HTTP_FORBIDDEN;
				}
			}
		}
	}
	
	// Return ok
	return NGX_HTTP_OK;
}

// Block IPv6 result
ngx_uint_t blockIpv6Result(const ngx_array_t *blockedAddressRanges, const struct sockaddr_in6 *address) {

	// Check if blocked address ranges exist
	if(blockedAddressRanges) {
	
		// Get address bytes
		const struct in6_addr *addressBytes = &address->sin6_addr;
	
		// Go through all blocked address ranges
		const BlockedAddressRange *blockedAddressRangesValues = blockedAddressRanges->elts;
		for(ngx_uint_t i = 0; i < blockedAddressRanges->nelts; ++i) {
		
			// Get blocked address range
			const BlockedAddressRange *blockedAddressRange = &blockedAddressRangesValues[i];
			
			// Check if blocked address range is for IPv6 addresses
			if(blockedAddressRange->type == AF_INET6) {
			
				// Check if address is in the blocked address range
				if(memcmp(addressBytes, &blockedAddressRange->ipv6StartOfRange, sizeof(struct in6_addr)) >= 0 && memcmp(addressBytes, &blockedAddressRange->ipv6EndOfRange, sizeof(struct in6_addr)) <= 0) {
				
					// Return forbidden
					return NGX_HTTP_FORBIDDEN;
				}
			}
		}
	}
	
	// Return ok
	return NGX_HTTP_OK;
}

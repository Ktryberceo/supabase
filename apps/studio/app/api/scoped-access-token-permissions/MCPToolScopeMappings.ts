import { constants, permissions } from '@supabase/shared-types'
import { mapValues, pickBy, uniq } from 'lodash'

import { McpMap } from '@/data/scoped-access-tokens/permission-scope-map-query'

const { OAuthScope } = constants

// Manually extracted from the platform MCP controller (`assertMcpOAuthScope` calls in
// mgmt-api routes/mcp/mcp.controller.ts) against @supabase/mcp-server-supabase's tool registry.
// Each value is a list of alternative OAuth-scope groups with the same semantics as
// `ScopeGroupAlternatives` (OR between groups, AND within a group).
// An empty group (`[[]]`) marks a tool that no permission gates; such tools are kept here for
// auditability against the platform controller but filtered out of the exported map.
const MCPToolOAuthScopeMapping: Record<string, constants.OAuthScope[][]> = {
  apply_migration: [[OAuthScope.DATABASE_WRITE]],
  // Pure cost-confirmation hash, no platform call
  confirm_cost: [[]],
  create_branch: [[OAuthScope.ENVIRONMENT_WRITE]],
  // create_project and get_cost are intentionally absent here: their handler authorization is
  // narrower than any OAuth scope bundle, so they're mapped directly to FGA permissions in
  // MCPToolFgaScopeMapping below.
  delete_branch: [[OAuthScope.ENVIRONMENT_WRITE]],
  deploy_edge_function: [[OAuthScope.EDGE_FUNCTIONS_WRITE]],
  // Requires read OR write depending on the tool's read_only parameter
  execute_sql: [[OAuthScope.DATABASE_READ], [OAuthScope.DATABASE_WRITE]],
  generate_typescript_types: [[OAuthScope.DATABASE_READ]],
  // Single tool with a `type` param covering both security and performance advisors
  get_advisors: [[OAuthScope.DATABASE_READ]],
  get_edge_function: [[OAuthScope.EDGE_FUNCTIONS_READ]],
  get_logs: [[OAuthScope.ANALYTICS_READ]],
  get_organization: [[OAuthScope.ORGANIZATIONS_READ]],
  get_project: [[OAuthScope.PROJECTS_READ]],
  get_project_url: [[OAuthScope.PROJECTS_READ]],
  get_publishable_keys: [[OAuthScope.SECRETS_READ]],
  // Platform does not assert this scope on the storage-config operations yet (fix pending on the
  // platform side) — mapped to the intended scope, not current develop behavior
  get_storage_config: [[OAuthScope.STORAGE_READ]],
  list_branches: [[OAuthScope.ENVIRONMENT_READ]],
  list_edge_functions: [[OAuthScope.EDGE_FUNCTIONS_READ]],
  // Runs executeSql(read_only: true) under the hood
  list_extensions: [[OAuthScope.DATABASE_READ]],
  list_migrations: [[OAuthScope.DATABASE_READ]],
  list_organizations: [[OAuthScope.ORGANIZATIONS_READ]],
  list_projects: [[OAuthScope.PROJECTS_READ]],
  list_storage_buckets: [[OAuthScope.STORAGE_READ]],
  // Runs executeSql(read_only: true) under the hood
  list_tables: [[OAuthScope.DATABASE_READ]],
  merge_branch: [[OAuthScope.ENVIRONMENT_WRITE]],
  pause_project: [[OAuthScope.PROJECTS_WRITE]],
  rebase_branch: [[OAuthScope.ENVIRONMENT_WRITE]],
  reset_branch: [[OAuthScope.ENVIRONMENT_WRITE]],
  restore_project: [[OAuthScope.PROJECTS_WRITE]],
  // Content API lookup, no platform authorization
  search_docs: [[]],
  // Same pending platform-side scope enforcement as get_storage_config
  update_storage_config: [[OAuthScope.STORAGE_WRITE]],
}

type ExtractIds<T> = {
  [K in keyof T]: {
    [P in keyof T[K]]: T[K][P] extends { id: infer I } ? I : never
  }
}
const FGA_PERMISSIONS = Object.fromEntries(
  Object.entries(permissions.FgaPermissions).map(([group, permissions]) => [
    group,
    Object.fromEntries(Object.entries(permissions).map(([key, { id }]) => [key, id])),
  ])
) as ExtractIds<typeof permissions.FgaPermissions>

// Duplicated from platform (packages/api-core/src/lib/permissions/fga-permissions.ts)
// Ideally, this could be exported from @supabase/shared-types
export const legacyOauthScopeToFgaPermissionMap: Record<string, string[]> = {
  'analytics:read': [
    FGA_PERMISSIONS.PROJECT.ANALYTICS_LOGS_READ,
    FGA_PERMISSIONS.PROJECT.ANALYTICS_USAGE_READ,
  ],
  'analytics:write': [],
  'analytics_config:read': [FGA_PERMISSIONS.PROJECT.ANALYTICS_CONFIG_READ],
  'analytics_config:write': [FGA_PERMISSIONS.PROJECT.ANALYTICS_CONFIG_WRITE],
  'auth:read': [FGA_PERMISSIONS.PROJECT.AUTH_CONFIG_READ],
  // Note(Hieu) Auth:write scope grants access to all auth config endpoints.
  // However, one endpoint requires minimum administrator role, so this oauth scope must also include the FGA PROJECT.ADMIN_WRITE permission
  'auth:write': [FGA_PERMISSIONS.PROJECT.ADMIN_WRITE, FGA_PERMISSIONS.PROJECT.AUTH_CONFIG_WRITE],
  'database:read': [
    FGA_PERMISSIONS.USER.SNIPPETS_READ,
    FGA_PERMISSIONS.PROJECT.ADVISORS_READ,
    FGA_PERMISSIONS.PROJECT.BACKUPS_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_CONFIG_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_JIT_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_MIGRATIONS_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_POOLING_CONFIG_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_READONLY_CONFIG_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_SSL_CONFIG_READ,
    FGA_PERMISSIONS.PROJECT.SNIPPETS_READ,
  ],
  'database:write': [
    FGA_PERMISSIONS.PROJECT.ADMIN_WRITE,
    FGA_PERMISSIONS.PROJECT.BACKUPS_WRITE,
    // Note(Hieu): Include database read permission here to align with the project query endpoint.
    // RLS and FGA guard this endpoint with database read first, then perform an additional check for write queries.
    // The OAuth guard requires database write directly, which causes a discrepancy error if we don't include read here.
    FGA_PERMISSIONS.PROJECT.DATABASE_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_CONFIG_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_MIGRATIONS_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_POOLING_CONFIG_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_READONLY_CONFIG_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_SSL_CONFIG_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_WEBHOOKS_CONFIG_WRITE,
  ],
  'domains:read': [
    FGA_PERMISSIONS.PROJECT.CUSTOM_DOMAIN_READ,
    FGA_PERMISSIONS.PROJECT.VANITY_SUBDOMAIN_READ,
  ],
  'domains:write': [
    FGA_PERMISSIONS.PROJECT.CUSTOM_DOMAIN_WRITE,
    FGA_PERMISSIONS.PROJECT.VANITY_SUBDOMAIN_WRITE,
  ],
  'edge_functions:read': [FGA_PERMISSIONS.PROJECT.EDGE_FUNCTIONS_READ],
  'edge_functions:write': [FGA_PERMISSIONS.PROJECT.EDGE_FUNCTIONS_WRITE],
  'environment:read': [
    FGA_PERMISSIONS.PROJECT.ACTION_RUNS_READ,
    FGA_PERMISSIONS.PROJECT.BRANCHING_DEVELOPMENT_READ,
    FGA_PERMISSIONS.PROJECT.BRANCHING_PRODUCTION_READ,
  ],
  'environment:write': [
    FGA_PERMISSIONS.PROJECT.ACTION_RUNS_WRITE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_DEVELOPMENT_CREATE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_DEVELOPMENT_DELETE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_DEVELOPMENT_WRITE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_PRODUCTION_CREATE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_PRODUCTION_DELETE,
    FGA_PERMISSIONS.PROJECT.BRANCHING_PRODUCTION_WRITE,
  ],
  'organizations:read': [
    FGA_PERMISSIONS.USER.ORGANIZATIONS_READ,
    FGA_PERMISSIONS.ORGANIZATION.ADMIN_READ,
    FGA_PERMISSIONS.ORGANIZATION.MEMBERS_READ,
  ],
  'organizations:write': [],
  'projects:read': [
    FGA_PERMISSIONS.USER.PROJECTS_READ,
    FGA_PERMISSIONS.ORGANIZATION.PROJECTS_READ,
    FGA_PERMISSIONS.PROJECT.ADMIN_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_NETWORK_BANS_READ,
    FGA_PERMISSIONS.PROJECT.DATABASE_NETWORK_RESTRICTIONS_READ,
  ],
  'projects:write': [
    FGA_PERMISSIONS.ORGANIZATION.ADMIN_WRITE,
    FGA_PERMISSIONS.ORGANIZATION.PROJECTS_CREATE,
    FGA_PERMISSIONS.PROJECT.ADMIN_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_NETWORK_BANS_WRITE,
    FGA_PERMISSIONS.PROJECT.DATABASE_NETWORK_RESTRICTIONS_WRITE,
  ],
  'rest:read': [FGA_PERMISSIONS.PROJECT.DATA_API_CONFIG_READ],
  'rest:write': [FGA_PERMISSIONS.PROJECT.DATA_API_CONFIG_WRITE],
  'secrets:read': [
    FGA_PERMISSIONS.PROJECT.API_GATEWAY_KEYS_READ,
    FGA_PERMISSIONS.PROJECT.AUTH_SIGNING_KEYS_READ,
    FGA_PERMISSIONS.PROJECT.EDGE_FUNCTIONS_SECRETS_READ,
  ],
  'secrets:write': [
    FGA_PERMISSIONS.PROJECT.API_GATEWAY_KEYS_WRITE,
    FGA_PERMISSIONS.PROJECT.AUTH_SIGNING_KEYS_WRITE,
    FGA_PERMISSIONS.PROJECT.EDGE_FUNCTIONS_SECRETS_WRITE,
  ],
  'storage:read': [
    FGA_PERMISSIONS.PROJECT.STORAGE_READ,
    FGA_PERMISSIONS.PROJECT.STORAGE_CONFIG_READ,
  ],
  'storage:write': [
    FGA_PERMISSIONS.PROJECT.STORAGE_WRITE,
    FGA_PERMISSIONS.PROJECT.STORAGE_CONFIG_WRITE,
  ],
}

// Tools whose MCP-handler authorization is narrower than any legacy OAuth scope bundle, mapped
// directly to the FGA permissions of the checks the handlers actually run. OAuth scope asserts
// are no-ops for PATs, so expanding the bundles would demand unrelated permissions (members,
// project-admin, network) and hide these tools from tokens that can actually use them.
// - get_cost: getOrganization -> READ organizations (organization_admin_read); listProjects
//   performs no permission check (results are only RLS-filtered)
// - create_project: the cost flow's getOrganization plus CREATE projects at the organization
//   level (organization_projects_create)
const MCPToolFgaScopeMapping: McpMap = {
  get_cost: [[FGA_PERMISSIONS.ORGANIZATION.ADMIN_READ]],
  create_project: [
    [FGA_PERMISSIONS.ORGANIZATION.ADMIN_READ, FGA_PERMISSIONS.ORGANIZATION.PROJECTS_CREATE],
  ],
}

/*
 * Build a map of MCP tools/FGA permissions by expanding each OAuth scope inside a group into the
 * FGA permissions it implies, preserving the alternative-group structure:
 * {
 *    execute_sql: [["database_read", ...], ["project_admin_write", "database_write", ...]]
 * }
 * Ungated tools (empty groups) are dropped so consumers can assume every group is non-empty.
 * The code is duplicated from platform until we find a better way to share those mappings
 */
export const MCPToolScopeMappings: McpMap = {
  ...pickBy(
    mapValues(MCPToolOAuthScopeMapping, (oAuthScopeGroups) =>
      oAuthScopeGroups
        .filter((group) => group.length > 0)
        .map((group) =>
          uniq(group.flatMap((oAuthScope) => legacyOauthScopeToFgaPermissionMap[oAuthScope]))
        )
    ),
    (groups) => groups.length > 0
  ),
  ...MCPToolFgaScopeMapping,
}

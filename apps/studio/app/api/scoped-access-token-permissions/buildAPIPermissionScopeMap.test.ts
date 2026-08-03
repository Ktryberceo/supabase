import { describe, expect, test } from 'vitest'

import { addMCPToolsToScopes, getEndpointsForAPI } from './buildAPIPermissionScopeMap'
import { MCPToolScopeMappings } from './MCPToolScopeMappings'
import { ScopeMap } from '@/data/scoped-access-tokens/permission-scope-map-query'

describe('getEndpointsForAPI', () => {
  const openAPISpecs = {
    paths: {
      '/v1/projects/{ref}/database/migrations': {
        get: {
          'x-fga-permissions': [['database_migrations_read']],
        },
        post: {
          'x-fga-permissions': [['database_migrations_write']],
        },
      },
      '/v1/projects/{ref}/database/migrations/{version}': {
        patch: {
          'x-fga-permissions': [['database_migrations_write']],
        },
      },
      // Alternative groups: development OR production (real shape of the branching endpoints)
      '/v1/projects/{ref}/branches': {
        get: {
          'x-fga-permissions': [['branching_development_read'], ['branching_production_read']],
        },
      },
      // No annotation -> not part of the map
      '/v1/projects/available-regions': {
        get: {},
      },
    },
  }

  test('indexes scopes and endpoints, preserving alternative permission groups', () => {
    const permissionScopeMap = getEndpointsForAPI(openAPISpecs)

    expect(permissionScopeMap).toEqual({
      scopes: {
        database_migrations_read: {
          endpoints: ['GET /v1/projects/{ref}/database/migrations'],
          mcp_tools: [],
        },
        database_migrations_write: {
          endpoints: [
            'POST /v1/projects/{ref}/database/migrations',
            'PATCH /v1/projects/{ref}/database/migrations/{version}',
          ],
          mcp_tools: [],
        },
        branching_development_read: {
          endpoints: ['GET /v1/projects/{ref}/branches'],
          mcp_tools: [],
        },
        branching_production_read: {
          endpoints: ['GET /v1/projects/{ref}/branches'],
          mcp_tools: [],
        },
      },
      endpoints: {
        'GET /v1/projects/{ref}/database/migrations': [['database_migrations_read']],
        'POST /v1/projects/{ref}/database/migrations': [['database_migrations_write']],
        'PATCH /v1/projects/{ref}/database/migrations/{version}': [['database_migrations_write']],
        'GET /v1/projects/{ref}/branches': [
          ['branching_development_read'],
          ['branching_production_read'],
        ],
      },
    })
  })

  test('drops empty permission groups and unannotated endpoints', () => {
    const { endpoints } = getEndpointsForAPI({
      paths: {
        '/v1/empty-groups': { get: { 'x-fga-permissions': [[], undefined] } },
        '/v1/unannotated': { get: {} },
      },
    })

    expect(endpoints).toEqual({})
  })
})

describe('addMCPToolsToScopes', () => {
  test('assigns tools to every scope in any of their groups, without duplicates', () => {
    const scopes: ScopeMap = {
      database_migrations_read: {
        endpoints: ['GET /v1/projects/{ref}/database/migrations'],
        mcp_tools: [],
      },
      database_migrations_write: { endpoints: [], mcp_tools: ['apply_migration'] },
    }

    addMCPToolsToScopes(scopes, {
      list_migrations: [['database_migrations_read']],
      apply_migration: [['database_migrations_write'], ['database_migrations_read']],
    })

    expect(scopes).toEqual({
      database_migrations_read: {
        endpoints: ['GET /v1/projects/{ref}/database/migrations'],
        mcp_tools: ['list_migrations', 'apply_migration'],
      },
      database_migrations_write: { endpoints: [], mcp_tools: ['apply_migration'] },
    })
  })

  test('initializes scopes that only MCP tools reference', () => {
    const scopes: ScopeMap = {}

    addMCPToolsToScopes(scopes, { update_storage_config: [['storage_write']] })

    expect(scopes.storage_write).toEqual({
      endpoints: [],
      mcp_tools: ['update_storage_config'],
    })
  })
})

describe('MCPToolScopeMappings', () => {
  test('maps cost-flow tools to the FGA checks their handlers actually run, not OAuth bundles', () => {
    // get_cost: getOrganization -> organization read; listProjects has no permission check
    expect(MCPToolScopeMappings.get_cost).toEqual([['organization_admin_read']])
    // create_project: cost flow's getOrganization + CREATE projects at the organization
    expect(MCPToolScopeMappings.create_project).toEqual([
      ['organization_admin_read', 'organization_projects_create'],
    ])
  })

  test('drops ungated tools and keeps every group non-empty', () => {
    expect(MCPToolScopeMappings).not.toHaveProperty('search_docs')
    expect(MCPToolScopeMappings).not.toHaveProperty('confirm_cost')
    for (const groups of Object.values(MCPToolScopeMappings)) {
      expect(groups.length).toBeGreaterThan(0)
      for (const group of groups) {
        expect(group.length).toBeGreaterThan(0)
        expect(group).not.toContain(undefined)
      }
    }
  })
})

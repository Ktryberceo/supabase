import lodash from 'lodash'
import z from 'zod'

// We don't have an OpenAPI that describes mcp tools security requirements so
// we have this hard coded file that must be updated when they change
import { MCPToolScopeMappings } from './MCPToolScopeMappings'
import {
  EndpointMap,
  McpMap,
  PermissionScopeMap,
  ScopeMap,
} from '@/data/scoped-access-tokens/permission-scope-map-query'
import { InternalServerError } from '@/lib/api/apiHelpers'

// Default lodash merge does not correctly merge arrays so this custom merger fixes it.
// Concat is safe here: v1 and v2 endpoint keys never collide, so the only arrays merged across
// specs are a scope's endpoint lists, whose entries are distinct.
function mergeArrays(objValue: unknown, srcValue: unknown) {
  if (Array.isArray(objValue) && Array.isArray(srcValue)) {
    return objValue.concat(srcValue)
  }
}

/*
 * Builds the permissions/endpoint mapping by fetching the OpenAPI specs for our v1 and v2 APIs.
 * @throws InternalServerError when it can't fetch the OpenAPI specs
 */
export const buildAPIPermissionScopeMap = async (): Promise<PermissionScopeMap> => {
  const [apiV1SpecsJSON, apiV2SpecsJSON] = await Promise.all([
    fetchAPIPermissionScope('v1'),
    fetchAPIPermissionScope('v2'),
  ])
  const permissionScopeMapV1 = getEndpointsForAPI(API_SPECS_SCHEMA.parse(apiV1SpecsJSON))
  const permissionScopeMapV2 = getEndpointsForAPI(API_SPECS_SCHEMA.parse(apiV2SpecsJSON))

  const permissionScope: PermissionScopeMap = lodash.mergeWith(
    { mcp_tools: MCPToolScopeMappings },
    permissionScopeMapV1,
    permissionScopeMapV2,
    mergeArrays
  )
  addMCPToolsToScopes(permissionScope.scopes, MCPToolScopeMappings)

  return permissionScope
}

// OPEN API specs look like this (only kept the parts we're interested in):
// {
//   "paths": {
//     "/v1/projects/{ref}/branches": {
//       "get": {
//         "x-fga-permissions": [
//           ["branching_development_read"],
//           ["branching_production_read"]
//         ]
//       }
//     }
//   }
// }
// The extension value is a list of alternative permission groups: a token needs ALL permissions
// of at least ONE group (OR between groups, AND within a group) — see `AuthWithFgaPermissions`
// in the mgmt-api. Groups must be preserved verbatim, not flattened, or OR-alternatives (e.g.
// development vs production branching) turn into impossible conjunctions.
export const getEndpointsForAPI = (
  apiSpecs: z.output<typeof API_SPECS_SCHEMA>
): Omit<PermissionScopeMap, 'mcp_tools'> => {
  const scopes: ScopeMap = {}
  const endpoints: EndpointMap = {}

  // Loop over each API path to record endpoint permission groups and index scopes -> endpoints
  Object.entries(apiSpecs.paths).forEach(([path, methods]) => {
    // Loop over each API path method (get, post, etc.)
    Object.entries(methods).forEach(([method, methodSpecs]) => {
      const endpoint = `${method.toUpperCase()} ${path}`
      const groups = (methodSpecs['x-fga-permissions'] ?? []).filter(
        (group): group is string[] => Array.isArray(group) && group.length > 0
      )
      if (groups.length === 0) return

      endpoints[endpoint] = groups

      groups.flat().forEach((permission) => {
        // Initialize scope object if needed
        scopes[permission] = scopes[permission] || { endpoints: [], mcp_tools: [] }

        if (!scopes[permission].endpoints.includes(endpoint)) {
          scopes[permission].endpoints.push(endpoint)
        }
      })
    })
  })

  return { scopes, endpoints }
}

// Assign the mcp tools to their scopes. Scopes referenced only by tools (no endpoint lists
// them, e.g. project_snippets_read) are initialized here so they don't vanish from the map.
export const addMCPToolsToScopes = (scopes: ScopeMap, mcp_tools: McpMap) => {
  Object.entries(mcp_tools).forEach(([mcpTool, toolScopeGroups]) => {
    toolScopeGroups.flat().forEach((toolScope) => {
      scopes[toolScope] = scopes[toolScope] || { endpoints: [], mcp_tools: [] }
      if (!scopes[toolScope].mcp_tools.includes(mcpTool)) {
        scopes[toolScope].mcp_tools.push(mcpTool)
      }
    })
  })
}

const NEXT_PUBLIC_API_DOMAIN = process.env.NEXT_PUBLIC_API_DOMAIN || 'https://api.supabase.com'

const fetchAPIPermissionScope = async (version: 'v1' | 'v2') => {
  try {
    const response = await fetch(`${NEXT_PUBLIC_API_DOMAIN}/api/${version}-json`, {
      method: 'get',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    if (response.ok) {
      return response.json()
    }
    const responseText = await response.text()

    const retryAfter = response.headers.get('Retry-After') ?? undefined
    throw new InternalServerError(`API v${version} responded with ${response.status}`, {
      status: response.status,
      body: responseText,
      ...(retryAfter !== undefined && { retryAfter }),
    })
  } catch (error: unknown) {
    if (error instanceof InternalServerError) {
      throw error
    }

    if (error instanceof Error) {
      throw new InternalServerError(error.message)
    }
  }
}

// Simplified OPEN API specs schemas that only defines what we care about for scoped tokens

const OPEN_API_PATH_METHOD_SCHEMA = z.object({
  'x-fga-permissions': z.array(z.string().array().optional()).optional(),
})

const API_SPECS_SCHEMA = z.object({
  paths: z.record(
    z.string(),
    z.record(
      z.enum(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace']),
      OPEN_API_PATH_METHOD_SCHEMA
    )
  ),
})

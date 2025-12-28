// Copyright 2025 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.detector;

import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;

import java.util.*;

/**
 * DefaultDetector is the default implementation of Detector interface.
 * It uses depth-first search to detect cycles in RBAC role inheritance graph.
 */
public class DefaultDetector implements Detector {

    /**
     * Checks whether the current status of the passed-in RoleManager contains logical errors (e.g., cycles in role inheritance).
     * @param rm RoleManager instance
     * @return If a cycle is found, return a description message in the form "Cycle detected: A -> B -> C -> A"; otherwise return null
     */
    @Override
    public String check(RoleManager rm) {
        if (!(rm instanceof DefaultRoleManager)) {
            throw new IllegalArgumentException("DefaultDetector only supports DefaultRoleManager");
        }
        
        DefaultRoleManager drm = (DefaultRoleManager) rm;
        
        // Build adjacency list from the role manager
        // Using local data structures to avoid sharing references with RoleManager's internal state
        Map<String, List<String>> graph = buildGraph(drm);
        
        // Perform DFS to detect cycles
        Set<String> visited = new HashSet<>();
        Set<String> recursionStack = new HashSet<>();
        Map<String, String> parent = new HashMap<>();
        
        for (String node : graph.keySet()) {
            if (!visited.contains(node)) {
                String cycle = dfs(node, graph, visited, recursionStack, parent);
                if (cycle != null) {
                    return cycle;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Builds a directed graph (adjacency list) from the DefaultRoleManager.
     * Each role points to the roles it inherits (its parent roles).
     */
    private Map<String, List<String>> buildGraph(DefaultRoleManager drm) {
        Map<String, List<String>> graph = new HashMap<>();
        
        try {
            // Use reflection to access the package-private allRoles field
            java.lang.reflect.Field allRolesField = DefaultRoleManager.class.getDeclaredField("allRoles");
            allRolesField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, ?> allRoles = (Map<String, ?>) allRolesField.get(drm);
            
            // Iterate through all roles and get their parent roles
            for (String roleName : allRoles.keySet()) {
                List<String> parentRoles = drm.getRoles(roleName);
                graph.put(roleName, new ArrayList<>(parentRoles));
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to access DefaultRoleManager internals", e);
        }
        
        return graph;
    }
    
    /**
     * Performs depth-first search to detect cycles in the graph using an iterative approach.
     * 
     * @param startNode Starting node for DFS
     * @param graph The adjacency list representation of the role inheritance graph
     * @param visited Set of all visited nodes
     * @param recursionStack Set of nodes in current DFS path (used to detect back edges)
     * @param parent Map to track parent of each node for cycle path reconstruction
     * @return Cycle description if found, null otherwise
     */
    private String dfs(String startNode, Map<String, List<String>> graph, Set<String> visited, 
                      Set<String> recursionStack, Map<String, String> parent) {
        // Use iterative DFS with explicit stack to avoid stack overflow on large graphs
        Stack<DFSState> stack = new Stack<>();
        stack.push(new DFSState(startNode, 0));
        visited.add(startNode);
        recursionStack.add(startNode);
        
        while (!stack.isEmpty()) {
            DFSState state = stack.peek();
            String node = state.node;
            List<String> neighbors = graph.get(node);
            
            if (neighbors == null || state.index >= neighbors.size()) {
                // All neighbors processed, backtrack
                stack.pop();
                recursionStack.remove(node);
                continue;
            }
            
            String neighbor = neighbors.get(state.index);
            state.index++;
            
            if (!visited.contains(neighbor)) {
                parent.put(neighbor, node);
                visited.add(neighbor);
                recursionStack.add(neighbor);
                stack.push(new DFSState(neighbor, 0));
            } else if (recursionStack.contains(neighbor)) {
                // Cycle detected! Build the cycle path
                parent.put(neighbor, node);
                return buildCyclePath(neighbor, node, parent);
            }
        }
        
        return null;
    }
    
    /**
     * Helper class to maintain DFS state for iterative traversal.
     */
    private static class DFSState {
        String node;
        int index; // Index of next neighbor to process
        
        DFSState(String node, int index) {
            this.node = node;
            this.index = index;
        }
    }
    
    /**
     * Builds a human-readable cycle path description.
     * 
     * @param cycleStart The node where the cycle was detected (the node being revisited)
     * @param cycleEnd The current node that creates the back edge to cycleStart
     * @param parent Map of parent relationships used to reconstruct the path
     * @return Cycle description in the form "Cycle detected: A -> B -> C -> A"
     */
    private String buildCyclePath(String cycleStart, String cycleEnd, Map<String, String> parent) {
        List<String> path = new ArrayList<>();
        
        // Build path from cycleEnd back to cycleStart
        String current = cycleEnd;
        while (current != null && !current.equals(cycleStart)) {
            path.add(0, current);
            current = parent.get(current);
        }
        
        // Add cycleStart at the beginning and end to show the complete cycle
        path.add(0, cycleStart);
        path.add(cycleStart);
        
        return "Cycle detected: " + String.join(" -> ", path);
    }
}

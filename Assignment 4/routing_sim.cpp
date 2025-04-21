#include <iostream>
#include <vector>
#include <limits>
#include <iomanip>
#include <queue>
using namespace std;

const int INF = 99999999;

void printDVRTables(const vector<vector<int>>& dist, const vector<vector<int>>& nextHop) {
    cout << "--- Distance Vector Routing Simulation ---\n";
    int n = dist.size();
    for (int i = 0; i < n; ++i) {
        cout << "Node " << i << " Routing Table:\n";
        cout << "Dest\tMetric\tNext Hop\n";
        for (int j = 0; j < n; ++j) {
            cout << j << "\t" << dist[i][j] << "\t";
            if (i == j) cout << "-";
            else cout << nextHop[i][j];
            cout << "\n";
        }
        cout << endl;
    }
}

void distanceVectorRouting(const vector<vector<int>>& adj) {
    int n = adj.size();
    vector<vector<int>> dist = adj;
    vector<vector<int>> nextHop(n, vector<int>(n, -1));

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            if (i == j) nextHop[i][j] = -1;
            else if (adj[i][j] < INF) nextHop[i][j] = j;
        }
    }

    bool updated;
    do {
        updated = false;
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                for (int k = 0; k < n; ++k) {
                    if (dist[i][k] + dist[k][j] < dist[i][j]) {
                        dist[i][j] = dist[i][k] + dist[k][j];
                        nextHop[i][j] = nextHop[i][k];
                        updated = true;
                    }
                }
            }
        }
    } while (updated);

    printDVRTables(dist, nextHop);
}

int findNextHop(int src, int dest, const vector<int>& prev) {
    int curr = dest;
    while (prev[curr] != -1 && prev[curr] != src) {
        curr = prev[curr];
    }
    return curr;
}

void linkStateRouting(const vector<vector<int>>& adj) {
    int n = adj.size();
    cout << "--- Link State Routing Simulation ---\n";
    for (int src = 0; src < n; ++src) {
        vector<int> dist(n, INF), prev(n, -1), visited(n, 0);
        dist[src] = 0;

        for (int i = 0; i < n; ++i) {
            int u = -1;
            for (int j = 0; j < n; ++j) {
                if (!visited[j] && (u == -1 || dist[j] < dist[u])) u = j;
            }
            if (u == -1 || dist[u] == INF) break;
            visited[u] = 1;

            for (int v = 0; v < n; ++v) {
                if (adj[u][v] < INF && dist[u] + adj[u][v] < dist[v]) {
                    dist[v] = dist[u] + adj[u][v];
                    prev[v] = u;
                }
            }
        }

        cout << "Node " << src << " Routing Table:\n";
        cout << "Dest\tMetric\tNext Hop\n";
        for (int dest = 0; dest < n; ++dest) {
            if (src == dest) {
                cout << dest << "\t" << dist[dest] << "\t-\n";
            } else {
                int next = findNextHop(src, dest, prev);
                cout << dest << "\t" << dist[dest] << "\t" << next << "\n";
            }
        }
        cout << endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: ./sim <inputfile>\n";
        return 1;
    }

    freopen(argv[1], "r", stdin);
    int n;
    cin >> n;
    vector<vector<int>> adj(n, vector<int>(n));

    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            cin >> adj[i][j];

    distanceVectorRouting(adj);
    linkStateRouting(adj);
    return 0;
}
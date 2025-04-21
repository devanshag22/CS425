# CS425 - Assignment 3: DVR and LSR Routing Simulation

This assignment implements the simulation of two fundamental routing algorithms—**Distance Vector Routing (DVR)** and **Link State Routing (LSR)** —using C++ with an adjacency matrix input to model a network of routers.

---

## Objective:

The goal is to simulate the operation of DVR and LSR algorithms and generate the corresponding routing tables for each node in the network. This simulation will demonstrate how routers compute the shortest or most optimal paths based on shared information.

---

## 📁 Files:

* `sim.cpp`: Main source file that simulates both DVR and LSR algorithms.
* `Makefile`: A simple build script to compile and run the simulator.
* `README.md`: This documentation file explaining the design, execution, and expected behavior.

---

## How to Compile:

1. Open a terminal and navigate to the directory containing the source code and Makefile.
2. Run:
   ```bash
   make
   ```
   This will compile the project and create an executable named `sim`.

---

## How to Run:

After compiling the code, execute the program as follows:

```bash
./sim inputfile.txt
```

Where `inputfile.txt` is the path to the file containing the adjacency matrix.

---

## Input Format:

The input is an **adjacency matrix** stored in a text file. The format is:

1. The first line contains an integer `n`, the number of nodes.
2. The next `n` lines each contain `n` integers, where the value at the `i-th` row and `j-th` column represents the cost between node `i` and node `j`.

- A value of `0` means no cost or no self-loop.
- A value of `9999` represents infinity (i.e., an unreachable or non-existent link).

### Sample Input (`inputfile.txt`):

```
4
0 10 100 30
10 0 20 40
100 20 0 10
30 40 10 0
```

---

## Output Format:

The program will simulate both algorithms and output the routing tables in the following format:

---

### Distance Vector Routing Simulation:

Each node prints its routing table **after each iteration** of table exchange. The final stable routing table will also be printed.

```
--- Distance Vector Routing Simulation ---
Node 0 Routing Table:
Dest Metric Next Hop
0    0      -
1    10     1
2    30     3
3    30     3
...
```
---

### Link State Routing Simulation:

Each node prints its routing table after running **Dijkstra’s algorithm** on the full topology.

```
--- Link State Routing Simulation ---
Node 1 Routing Table:
Dest Metric Next Hop
0    10     0
2    20     2
3    30     3
...
```

---

## Algorithm Details:

### Distance Vector Routing (DVR)

- Each node maintains a distance vector: the cost to reach every other node.
- Initially:
  - Cost to self = 0
  - Cost to direct neighbors = edge weight
  - Cost to non-neighbors = ∞
- Nodes update their vectors by applying **Bellman-Ford**:
  ```
  D(i, j) = min over all k ( cost(i, k) + D(k, j) )
  ```
- Repeats until no update occurs in an iteration (convergence).

### Link State Routing (LSR)

- Each node knows the full network topology.
- It runs **Dijkstra's algorithm** to compute the shortest path to every node.
- For each destination, the next hop is traced back using the `prev[]` array from Dijkstra.


## Contributors and Contributions:

- Ankit Kaushik (220158) – 33.33%  
- Devansh Agrawal (220340) – 33.33%  
- Harshit Srivastava (220444) – 33.33%  

---

## References:

- [RFC 1058 - Routing Information Protocol (RIP)](https://tools.ietf.org/html/rfc1058) – for understanding DVR.
- [RFC 2328 - OSPF Version 2](https://tools.ietf.org/html/rfc2328) – for understanding LSR.
- Course Slides and Assignment Description (CS425, Spring 2025)

#pragma once

#include "types.h"

#include <iostream>
#include <string>
#include <stdint.h>
#include <ctime>
#include <memory.h>

class Node
{
public:
    char genes[KEY_LEN + 1];
    int fitness;

    Node()
        : fitness(0)
    {
        memset(genes, 0, sizeof(genes));
    }

    void print()
    {
        printf("%s %d\n", genes, fitness);
    }
};

class GeneticSolver
{
public:
    GeneticSolver(std::string genes, int maxAttempts)
        : kABC(genes), kMaxAttempts(maxAttempts), kABCLen(kABC.length())
        { }

    bool brute();
    //---
    Node bestParent;

protected:
    virtual int getFitness(const Node& node) = 0;

    void generateParent(Node& rv);
    void mutate(const Node& p, Node& c);
    void crossover(const Node& p, const Node& bp, Node& c);
    //---
    const int kMaxAttempts;
    const std::string kABC;
    const size_t kABCLen;
};

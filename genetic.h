#pragma once

#include "types.h"

#include <iostream>
#include <string>
#include <stdint.h>
#include <ctime>
#include <memory.h>
#include <vector>

struct Node
{
    enum Strategy
    {
        NS_Unknown,
        NS_Random,
        NS_Mutate,
        NS_Crossover
    };
    char genes[KEY_LEN + 1];
    int fitness;
    Strategy strategy;

    Node()
        : fitness(0)
        , strategy(NS_Unknown)
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
        {
            //kABCLen = kABC.length();
        }

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

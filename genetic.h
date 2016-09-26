#pragma once

#include "types.h"
#include <functional>
#include <string>

// fwd
struct Node;
typedef std::function<int (const std::string& genes)> GetFitness_t;
typedef std::function<bool (int fitness)> IsFinishedCmp_t;
typedef std::function<bool (int oldFitness, int newFitness)> IsBetterCmt_t;

class GeneticSolver
{
public:
    GeneticSolver(const std::string& genes,
                  int outputLen,
                  int maxAttempts,
                  GetFitness_t fnGetFitness,
                  IsFinishedCmp_t fnIsFinishedCmp,
                  IsBetterCmt_t fnIsBetterCmp);

    bool brute(std::string& result);

private:
    void generateParent(Node& rv);
    void mutate(const Node& p, Node& c);
    void crossover(const Node& p, const Node& bp, Node& c);

private:
    const int MaxAttempts_;
    const std::string Genes_;
    const int OutputLen_;

    GetFitness_t GetFitness_;
    IsFinishedCmp_t IsFinishedCmp_;
    IsBetterCmt_t IsBetterCmp_;
};

bool verifyKey(const std::string& key, std::string* lpExpandedCleanKey16);

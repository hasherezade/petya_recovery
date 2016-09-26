// Author of implementation: AlexWMF
// Genetic algorithm taken from https://github.com/handcraftsman/GeneticPy
#include "genetic.h"
#include <iostream>
#include <string>
#include <stdint.h>
#include <ctime>
#include <memory.h>
#include <limits.h>

#include "decryptor.h"
struct Node
{
    std::string genes;
    uint32_t fitness;

    Node() = delete;

    explicit Node(int len)
        : fitness(UINT32_MAX)
        , genes(len, '\0')
    {
    }

    void print()
    {
        printf("%s %d\n", genes.c_str(), fitness);
    }
};


GeneticSolver::GeneticSolver(const std::string& genes,
                             int outputLen,
                             int maxAttempts,
                             GetFitness_t fnGetFitness,
                             IsFinishedCmp_t fnIsFinishedCmp,
                             IsBetterCmt_t fnIsBetterCmp)
    : Genes_(genes)
    , MaxAttempts_(maxAttempts)
    , OutputLen_(outputLen)
    , GetFitness_(fnGetFitness)
    , IsFinishedCmp_(fnIsFinishedCmp)
    , IsBetterCmp_(fnIsBetterCmp)
{
}

void GeneticSolver::generateParent(Node& rv)
{
    for (int i = 0; i < OutputLen_; ++i)
        rv.genes[i] = Genes_[rand() % Genes_.length()];
    rv.fitness = GetFitness_(rv.genes);
}

void GeneticSolver::mutate(const Node& p, Node& c)
{
    c = p;
    c.genes[rand() % OutputLen_] = Genes_[rand() % Genes_.length()];

    c.fitness = GetFitness_(c.genes);
}

void GeneticSolver::crossover(const Node& p, const Node& bp, Node& c)
{
    c = p;
    const int idx = rand() % OutputLen_;
    c.genes[idx] = bp.genes[idx];
    c.fitness = GetFitness_(c.genes);
}

bool GeneticSolver::brute(std::string& result)
{
    srand(time(NULL));

    Node bestParent {OutputLen_};
    generateParent(bestParent);
    bestParent.print();

    while (!IsFinishedCmp_(bestParent.fitness))
    {
        Node parent {OutputLen_};
        generateParent(parent);
        int attempts = 0;

        while (attempts < MaxAttempts_)
        {
            Node child {OutputLen_};
            if ((rand() % 100) / 50 == 0)
                mutate(parent, child);
            else
                crossover(parent, bestParent, child);

            if (IsBetterCmp_(parent.fitness, child.fitness))
            {
                parent = child;
                attempts = 0;
            }
            attempts++;

            if (IsBetterCmp_(bestParent.fitness, parent.fitness))
            {
                std::swap(bestParent, parent);
                bestParent.print();
                if (bestParent.fitness == 0) break;
            }
        }
    }
    result = bestParent.genes;
    return true;
}

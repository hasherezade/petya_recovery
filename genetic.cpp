#include "genetic.h"

void GeneticSolver::generateParent(Node& rv)
{
    rv.strategy = Node::NS_Random;
    for (int i = 0; i < KEY_LEN; ++i)
        rv.genes[i] = kABC[rand() % kABCLen];
    rv.fitness = getFitness(rv);
}

void GeneticSolver::mutate(const Node& p, Node& c)
{
    c = p;
    c.genes[rand() % KEY_LEN] = kABC[rand() % kABCLen];

    c.fitness = getFitness(c);
    c.strategy = Node::NS_Mutate;
}

void GeneticSolver::crossover(const Node& p, const Node& bp, Node& c)
{
    c = p;
    const int idx = rand() % KEY_LEN;
    c.genes[idx] = bp.genes[idx];
    c.fitness = getFitness(c);
    c.strategy = Node::NS_Crossover;
}

bool GeneticSolver::brute()
{
    srand(time(NULL));

    generateParent(bestParent);
    bestParent.print();

    while (bestParent.fitness > 0)
    {
        Node parent;
        generateParent(parent);
        int attempts = 0;

        while (attempts < kMaxAttempts)
        {
            Node child;
            if ((rand() % 100) / 50 == 0)
                mutate(parent, child);
            else
                crossover(parent, bestParent, child);

            if (child.fitness < parent.fitness)
            {
                parent = child;
                attempts = 0;
            }
            attempts++;

            if (parent.fitness < bestParent.fitness)
            {
                Node tmp = bestParent;
                bestParent = parent;
                parent = tmp;

                bestParent.print();
            }
        }
    }
    return true;
}

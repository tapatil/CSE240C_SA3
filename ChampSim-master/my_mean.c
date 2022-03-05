#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>

#define _DIGITS 10

int main(int argc, char **argv)
{
    FILE * fPtr;
    double values;
    double norm = 1.0;
    double geomean = 1.0;
    double average = 0.0;
    double i = 0;

    fPtr = fopen(argv[1], "r");
    if(fPtr == NULL)
    {
        printf("Unable to open file.\n");
        exit(EXIT_FAILURE);
    }

    if(argc >= 2) {
        norm = atof(argv[2]);
        if(norm == 0) {
            printf("norm = 0. Cannot divide by zero.\n");
            exit(EXIT_FAILURE);
        }
    }

    while(1){
        if(fscanf(fPtr, "%lf", &values) != 1) {
            break;
        }
        geomean *= (values/norm);
        average += (values/norm);
        i = i + 1.0;
    }

    if(i != 0) {
        geomean = (double) pow(geomean, (double)(1.0/i) );
        average = average/i;
    }

    printf("The Geometric Mean is: %.*lf\n", _DIGITS, geomean);
    printf("The Arithmatic Mean is: %.*lf\n", _DIGITS, average);

    fclose(fPtr);
    return 0;
}
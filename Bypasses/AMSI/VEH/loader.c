#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    /*
        La technique VEH  repose sur 3 principes.
            - Les scans AMSI sont originiaure de la DLL amsi.dll et plus précisément de la fonction : amsiscanbuffer()
            - Pour l'eviter on va donc rediriger le flow de cette fonction pour que la fonction se termine prématurément
            - pour se faire on va effectuer un HWBP (hardware breakpoint) sur l'entrypoint des fonction et faire les modifier le contexte (RIP + RAX + RSP)
    */

    printf("[*] ");
    
    return 0;
}
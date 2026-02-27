#include <stdio.h>
#include <string.h>

int check_password(char *input) {
    if (strcmp(input, "secret123") == 0) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    
    if (check_password(argv[1])) {
        printf("Access granted!\n");
        return 0;
    } else {
        printf("Access denied!\n");
        return 1;
    }
}

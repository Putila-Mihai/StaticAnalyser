#include <stdio.h>
#include <string.h>

void greet(const char* name) {
    printf("Hello, %s!\n", name);
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void reverse(char *str) {
    int i, j;
    char temp;
    for (i = 0, j = strlen(str) - 1; i < j; i++, j--) {
        temp = str[i];
        str[i] = str[j];
        str[j] = temp;
    }
}

int main() {
    char name[] = "botnet";
    greet(name);

    int n = 5;
    printf("Factorial of %d is %d\n", n, factorial(n));

    char str[] = "mirai";
    reverse(str);
    printf("Reversed string: %s\n", str);

    return 0;
}

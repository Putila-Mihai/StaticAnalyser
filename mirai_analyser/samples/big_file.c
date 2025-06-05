#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

// Enums
typedef enum {
    LOW, MEDIUM, HIGH
} Level;

// Structs
typedef struct {
    int id;
    char name[50];
    Level priority;
} Task;

void print_task(Task t) {
    printf("Task ID: %d, Name: %s, Priority: %d\n", t.id, t.name, t.priority);
}

// Math function
double compute_area(double radius) {
    return M_PI * radius * radius;
}

// Recursive function
int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// File writing
void save_to_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        perror("File opening failed");
        return;
    }
    fputs(content, f);
    fclose(f);
}

// Dynamic memory
char* create_message(const char* base, int id) {
    char* buffer = (char*)malloc(100);
    snprintf(buffer, 100, "%s #%d", base, id);
    return buffer;
}

// Switch example
void handle_level(Level l) {
    switch (l) {
        case LOW: puts("Low level"); break;
        case MEDIUM: puts("Medium level"); break;
        case HIGH: puts("High level"); break;
        default: puts("Unknown level");
    }
}

int main() {
    srand(time(NULL));

    Task tasks[5];
    for (int i = 0; i < 5; i++) {
        tasks[i].id = i + 1;
        snprintf(tasks[i].name, sizeof(tasks[i].name), "Task_%d", i + 1);
        tasks[i].priority = rand() % 3;
    }

    for (int i = 0; i < 5; i++) {
        print_task(tasks[i]);
        handle_level(tasks[i].priority);
    }

    double r = 5.0;
    printf("Area of circle with radius %.2f: %.2f\n", r, compute_area(r));

    int fib = 10;
    printf("Fibonacci(%d) = %d\n", fib, fibonacci(fib));

    char* message = create_message("Hello from task", 42);
    printf("Generated message: %s\n", message);
    save_to_file("output.txt", message);
    free(message);

    return 0;
}

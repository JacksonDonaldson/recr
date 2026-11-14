/*
 * A small, self-contained C program with 32 functions, including main.
 *
 * It is intentionally compiled at -O0 so every function survives as its own
 * symbol, making it useful as a codezip test input.  The functions cover
 * arithmetic, loops, bit operations, and array manipulation.
 */

#include <stdint.h>
#include <stdio.h>

int add(int a, int b)
{
    return a + b;
}

int subtract(int a, int b)
{
    return a - b;
}

int multiply(int a, int b)
{
    return a * b;
}

int divide_safe(int a, int b)
{
    if (b == 0) {
        return 0;
    }
    return a / b;
}

int modulo_safe(int a, int b)
{
    if (b == 0) {
        return 0;
    }
    return a % b;
}

int min_int(int a, int b)
{
    return a < b ? a : b;
}

int max_int(int a, int b)
{
    return a > b ? a : b;
}

int clamp(int value, int low, int high)
{
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int abs_int(int value)
{
    return value < 0 ? -value : value;
}

int sign(int value)
{
    return (value > 0) - (value < 0);
}

int square(int value)
{
    return value * value;
}

int cube(int value)
{
    return value * value * value;
}

int sum_to(int n)
{
    int total = 0;

    for (int i = 1; i <= n; ++i) {
        total += i;
    }
    return total;
}

unsigned long long factorial(unsigned n)
{
    unsigned long long result = 1;

    for (unsigned i = 2; i <= n; ++i) {
        result *= i;
    }
    return result;
}

int gcd(int a, int b)
{
    a = abs_int(a);
    b = abs_int(b);

    while (b != 0) {
        int remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

int lcm(int a, int b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return abs_int((a / gcd(a, b)) * b);
}

int is_even(int value)
{
    return (value % 2) == 0;
}

int is_odd(int value)
{
    return (value % 2) != 0;
}

int popcount(uint32_t value)
{
    int count = 0;

    while (value != 0) {
        count += (int)(value & 1u);
        value >>= 1;
    }
    return count;
}

uint32_t reverse_bits(uint32_t value)
{
    uint32_t result = 0;

    for (int i = 0; i < 32; ++i) {
        result = (result << 1) | (value & 1u);
        value >>= 1;
    }
    return result;
}

uint32_t rotate_left(uint32_t value, unsigned amount)
{
    amount %= 32u;
    return (value << amount) | (value >> ((32u - amount) % 32u));
}

uint32_t rotate_right(uint32_t value, unsigned amount)
{
    amount %= 32u;
    return (value >> amount) | (value << ((32u - amount) % 32u));
}

uint32_t checksum(const char *text)
{
    uint32_t sum = 2166136261u;

    while (*text != '\0') {
        sum ^= (uint32_t)(unsigned char)*text;
        sum *= 16777619u;
        ++text;
    }
    return sum;
}

int count_bytes(const char *text, char needle)
{
    int count = 0;

    while (*text != '\0') {
        if (*text == needle) {
            ++count;
        }
        ++text;
    }
    return count;
}

int find_byte(const char *text, char needle)
{
    int index = 0;

    while (*text != '\0') {
        if (*text == needle) {
            return index;
        }
        ++index;
        ++text;
    }
    return -1;
}

void reverse_array(int *values, int count)
{
    for (int i = 0, j = count - 1; i < j; ++i, --j) {
        int temporary = values[i];
        values[i] = values[j];
        values[j] = temporary;
    }
}

int sum_array(const int *values, int count)
{
    int total = 0;

    for (int i = 0; i < count; ++i) {
        total += values[i];
    }
    return total;
}

int max_array(const int *values, int count)
{
    int maximum = values[0];

    for (int i = 1; i < count; ++i) {
        if (values[i] > maximum) {
            maximum = values[i];
        }
    }
    return maximum;
}

void bubble_sort(int *values, int count)
{
    for (int i = 0; i < count - 1; ++i) {
        for (int j = 0; j < count - i - 1; ++j) {
            if (values[j] > values[j + 1]) {
                int temporary = values[j];
                values[j] = values[j + 1];
                values[j + 1] = temporary;
            }
        }
    }
}

int binary_search(const int *values, int count, int target)
{
    int low = 0;
    int high = count - 1;

    while (low <= high) {
        int middle = low + (high - low) / 2;

        if (values[middle] == target) {
            return middle;
        }
        if (values[middle] < target) {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    return -1;
}

int main(void)
{
    int values[] = {9, 3, 7, 1, 5, 3, 8, 2};
    const int count = (int)(sizeof(values) / sizeof(values[0]));
    const char *text = "banana";
    int total = 0;
    unsigned long long fact;

    total += add(7, 5);
    total += subtract(20, 8);
    total += multiply(6, 7);
    total += divide_safe(42, 6);
    total += divide_safe(1, 0);
    total += modulo_safe(43, 6);
    total += min_int(4, 9);
    total += max_int(4, 9);
    total += clamp(17, 0, 10);
    total += abs_int(-13);
    total += sign(-3);
    total += square(6);
    total += cube(3);
    total += sum_to(10);
    total += gcd(84, 30);
    total += lcm(21, 6);
    total += is_even(10);
    total += is_odd(10);
    total += popcount(0xF0F0u);
    total += (int)(reverse_bits(0x12345678u) & 0xFFFu);
    total += (int)(rotate_left(0x12345678u, 8u) & 0xFFFu);
    total += (int)(rotate_right(0x12345678u, 8u) & 0xFFFu);
    total += (int)(checksum("codezip") & 0xFFFu);
    total += count_bytes(text, 'a');
    total += find_byte(text, 'n');
    total += sum_array(values, count);
    total += max_array(values, count);

    reverse_array(values, count);
    bubble_sort(values, count);
    total += binary_search(values, count, 5);

    fact = factorial(6);
    printf("total=%d factorial=%llu first=%d last=%d\n",
           total, fact, values[0], values[count - 1]);

    return 0;
}

/*
 * Deliberately never called.  The unreferenced-function optimizer must
 * identify this function and mark its whole extent as free space.
 */
int unreferenced_function(int value)
{
    int total = 0;

    for (int i = 0; i < value; ++i) {
        total += i * 2;
    }
    return total;
}

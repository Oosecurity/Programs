def has_duplicate(arr):
    n = len(arr)
    for i in range(n):
        for j in range(i + 1, n):
            if arr[i] == arr[j]:
                return True
    return False

# Example usage:
my_array = [1, 2, 3, 4, 5, 2]
if has_duplicate(my_array):
    print("The array has at least two identical numbers.")
else:
    print("The array does not have at least two identical numbers.")

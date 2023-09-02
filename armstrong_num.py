# Armstrong number program using while loop
num = int(input("Please give a number: "))
sum = 0 
temp = num
# count the number of digits in input
count = len(str(num)) 
# loop on each digit and calculate the sum
while temp > 0:
    digit = temp % 10
    sum += digit ** count
    print(sum)
    temp //= 10 
# check if the number is an Armstrong or not
if num == sum:
    print("Given ",num, "is an Armstrong number")
else:
    print("Given ",num, "is not an Armstrong number")
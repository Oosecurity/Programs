num = int(input("please give a number: "))
sum=0
for i in range(1,(num//2)+1):
    remainder = num % i
    if remainder == 0:
        sum = sum + i
if sum == num:
    print("given input is perfect number")
else:
    print("given input is not a perfect number") 
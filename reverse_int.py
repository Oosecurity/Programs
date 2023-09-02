#Print with slicing str
num = int(input("Please give a number: "))
print("Your number is : %d" %num)
rev = int(str(num)[::-1])
print("After reverse the number:", rev)


#Reverse with while
n = int(input("Please give a number: "))
print("Before reverse your number is : %d" %n)
reverse = 0
while n!=0:
    reverse = reverse*10 + n%10     
    n = (n//10)
print("After reverse : %d" %reverse) 


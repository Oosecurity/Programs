import random

def display_welcome_message():
    print("""
====================================
  Welcome to the Number Guessing Game!
====================================
A secret number between 1 and 20 has been chosen.
You have 8 tries to guess it correctly.
Good luck!
""")

def display_congratulations_message(guess):
    print(f"""
***********************
  Congratulations!
***********************
You guessed the secret number: {guess}
You win!
""")

def display_game_over_message(secret):
    print(f"""
****************************
  Game Over!
****************************
The secret number was: {secret}
Better luck next time!
""")

def play_game():
    number_of_guesses = 8
    secret = random.randint(1, 20)
    
    display_welcome_message()
    
    while number_of_guesses > 0:
        print(f"Guess the number! You have {number_of_guesses} tries left.")
        try:
            guess = int(input("Enter your guess: "))
        except ValueError:
            print("Please enter a valid number.")
            continue
        
        number_of_guesses -= 1
        
        if guess > secret:
            print("Your guess is too high.")
        elif guess < secret:
            print("Your guess is too low.")
        else:
            display_congratulations_message(guess)
            break
    else:
        display_game_over_message(secret)

play_game()

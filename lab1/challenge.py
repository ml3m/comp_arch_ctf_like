#!/usr/local/bin/python3
import random
import os

def generate_random_number():
    return random.randint(0, 2**64 - 1)

def main():
    i = 1
    while i < 50:
        random_num = generate_random_number()
        user_input = input(f"Enter the base2 representation of the number {random_num} :")
        
        try:
            user_input = int(user_input, 2)
            if user_input == random_num:
                print("[*] Correct!")
                i += 1
            else:
                print(f"[*] Wrong!")
                i = 1

        except ValueError:
            print("Invalid input. Please enter a valid base2 representation.")

    flag = os.environ['FLAG']
    print(f"Congratulations! Here is your well-deserved flag: {flag}")

if __name__ == "__main__":
    main()

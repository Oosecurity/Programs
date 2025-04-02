import tkinter as tk
import random
from snake_ai import SnakeAI  # Import the AI logic

class SnakeGame:
    def __init__(self, master):
        self.master = master
        self.master.title("Snake Game")
        self.canvas = tk.Canvas(master, width=400, height=400, bg="lightgray")  # Softer background color
        self.canvas.pack()
        self.snake = [(20, 20)]
        self.food = None
        self.direction = "Right"
        self.running = True
        self.ai = SnakeAI()  # Initialize the AI
        self.create_snake()
        self.spawn_food()
        self.update_game()

    def create_snake(self):
        self.canvas.delete("snake")  # Clear previous snake rendering
        for x, y in self.snake:
            self.canvas.create_oval(x, y, x + 20, y + 20, fill="mediumseagreen", outline="darkgreen", tag="snake")  # Ensure circular segments

    def spawn_food(self):
        if self.food:
            self.canvas.delete(self.food)
        x = random.randint(0, 19) * 20
        y = random.randint(0, 19) * 20
        self.food = self.canvas.create_oval(x, y, x + 20, y + 20, fill="gold", outline="darkgoldenrod", tag="food")  # Softer food color

    def update_game(self):
        if not self.running:
            return
        x, y = self.snake[0]

        # Get food coordinates
        food_coords = self.canvas.coords(self.food)
        food_position = (food_coords[0], food_coords[1])  # Extract top-left corner of the food

        # Use AI to determine the next direction
        self.direction = self.ai.get_next_move(self.snake, food_position, self.direction)

        if self.direction == "Up":
            y -= 20
        elif self.direction == "Down":
            y += 20
        elif self.direction == "Left":
            x -= 20
        elif self.direction == "Right":
            x += 20
        new_head = (x, y)

        # Check for collisions
        if (
            x < 0 or x >= 400 or y < 0 or y >= 400 or
            new_head in self.snake
        ):
            self.running = False
            self.create_snake()  # Keep the snake visible
            self.canvas.create_text(200, 200, text="Game Over", fill="white", font=("Arial", 24))
            return

        # Check for food
        if self.canvas.coords(self.food) == [x, y, x + 20, y + 20]:
            self.snake.insert(0, new_head)
            self.spawn_food()
        else:
            self.snake.insert(0, new_head)
            tail = self.snake.pop()
            self.canvas.delete("snake")
            self.create_snake()

        self.master.after(100, self.update_game)

if __name__ == "__main__":
    root = tk.Tk()
    game = SnakeGame(root)
    root.mainloop()

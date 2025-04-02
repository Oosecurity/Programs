class SnakeAI:
    def get_next_move(self, snake, food_position, current_direction):
        head_x, head_y = snake[0]
        food_x, food_y = food_position  # Use the passed food position

        # Calculate possible moves
        moves = {
            "Up": (head_x, head_y - 20),
            "Down": (head_x, head_y + 20),
            "Left": (head_x - 20, head_y),
            "Right": (head_x + 20, head_y),
        }

        # Prioritize moves toward the food
        def distance_to_food(move):
            x, y = moves[move]
            return abs(x - food_x) + abs(y - food_y)

        # Filter valid moves (avoid collisions with walls and the snake's body)
        valid_moves = [
            move for move in moves
            if moves[move] not in snake and 0 <= moves[move][0] < 400 and 0 <= moves[move][1] < 400
        ]

        # If there are valid moves, choose the one that minimizes the distance to the food
        if valid_moves:
            # Sort valid moves by distance to food and return the best one
            return min(valid_moves, key=distance_to_food)

        # If no valid moves, try to avoid immediate collision by choosing any valid move
        for move in moves:
            if moves[move] not in snake and 0 <= moves[move][0] < 400 and 0 <= moves[move][1] < 400:
                return move

        # If no safe moves are available, keep moving in the current direction
        return current_direction

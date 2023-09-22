import random

# Minimax algorithm with alpha-beta pruning
def minimax(board, depth, maximizingPlayer):
    if checkHorizontle(board) or checkRow(board) or checkDiag(board):
        if maximizingPlayer:
            return -1  # AI wins
        else:
            return 1   # Player wins
    elif "-" not in board:
        return 0  # It's a tie

    if maximizingPlayer:
        maxEval = float("-inf")
        for i in range(9):
            if board[i] == "-":
                board[i] = AI_PLAYER
                eval = minimax(board, depth + 1, False)
                board[i] = "-"
                if eval == 1:
                    return eval  # Prioritize winning move
                maxEval = max(maxEval, eval)
        return maxEval
    else:
        minEval = float("inf")
        for i in range(9):
            if board[i] == "-":
                board[i] = currentPlayer
                eval = minimax(board, depth + 1, True)
                board[i] = "-"
                if eval == -1:
                    return eval  # Block player's winning move
                minEval = min(minEval, eval)
        return minEval


# AI's move
def computer(board):
    if currentPlayer == AI_PLAYER:
        bestMove = None
        bestEval = float("-inf")
        for i in range(9):
            if board[i] == "-":
                board[i] = AI_PLAYER
                eval = minimax(board, 0, False)
                board[i] = "-"
                if eval > bestEval:
                    bestEval = eval
                    bestMove = i
        board[bestMove] = AI_PLAYER
        switchPlayer()

board = ["-", "-", "-",
        "-", "-", "-",
        "-", "-", "-"]
currentPlayer = "X"
winner = None
gameRunning = True

# game board
def printBoard(board):
    print(board[0] + " | " + board[1] + " | " + board[2])
    print("---------")
    print(board[3] + " | " + board[4] + " | " + board[5])
    print("---------")
    print(board[6] + " | " + board[7] + " | " + board[8])


# take player input
def playerInput(board):
    while True:
        inp = int(input("Select a spot 1-9: "))
        if inp < 1 or inp > 9:
            print("Invalid input. Please choose a number between 1 and 9.")
        elif board[inp - 1] != "-":
            print("Oops! That spot is already taken. Choose another spot.")
        else:
            board[inp - 1] = currentPlayer
            break


# check for win or tie
def checkHorizontle(board):
    global winner
    if board[0] == board[1] == board[2] and board[0] != "-":
        winner = board[0]
        return True
    elif board[3] == board[4] == board[5] and board[3] != "-":
        winner = board[3]
        return True
    elif board[6] == board[7] == board[8] and board[6] != "-":
        winner = board[6]
        return True

def checkRow(board):
    global winner
    if board[0] == board[3] == board[6] and board[0] != "-":
        winner = board[0]
        return True
    elif board[1] == board[4] == board[7] and board[1] != "-":
        winner = board[1]
        return True
    elif board[2] == board[5] == board[8] and board[2] != "-":
        winner = board[3]
        return True


def checkDiag(board):
    global winner
    if board[0] == board[4] == board[8] and board[0] != "-":
        winner = board[0]
        return True
    elif board[2] == board[4] == board[6] and board[4] != "-":
        winner = board[2]
        return True


def checkIfWin(board):
    global gameRunning
    if checkHorizontle(board) or checkRow(board) or checkDiag(board):
        printBoard(board)
        print(f"The winner is {winner}!")
        gameRunning = False


    elif checkRow(board):
        printBoard(board)
        print(f"The winner is {winner}!")
        gameRunning = False

    elif checkDiag(board):
        printBoard(board)
        print(f"The winner is {winner}!")
        gameRunning = False


def checkIfTie(board):
    global gameRunning
    if "-" not in board:
        printBoard(board)
        print("It is a tie!")
        gameRunning = False


# switch player
def switchPlayer():
    global currentPlayer
    if currentPlayer == "X":
        currentPlayer = "O"
    else:
        currentPlayer = "X"


def computer(board):
    while currentPlayer == "O":
        position = random.randint(0, 8)
        if board[position] == "-":
            board[position] = "O"
            switchPlayer()


while gameRunning:
    printBoard(board)
    playerInput(board)
    checkIfWin(board)
    checkIfTie(board)
    switchPlayer()
    computer(board)
    checkIfWin(board)
    checkIfTie(board)



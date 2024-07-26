# Encrypted Chat

This program is a simple encrypted chat client that communicates via a JSON file. It provides features for user authentication, sending and receiving messages, and monitoring and managing chat messages.

## Features

- **User Authentication**: Authenticate users based on username and password.
- **Message Storage**: Save and retrieve messages in a JSON file.
- **Real-Time Monitoring**: Monitor the JSON file for changes and automatically update the chat.
- **Encryption**: Encrypt and decrypt messages to maintain privacy.

## Requirements

- .NET Core or .NET Framework (depending on the environment)
- [Newtonsoft.Json](https://www.nuget.org/packages/Newtonsoft.Json/) (for JSON processing)

## Installation

1. Clone this repository or download the source files.
2. Ensure that you have installed the required NuGet packages.
3. Configure the path to the JSON file in the `Program.cs` file (`jsonFilePath`).

## Usage

1. **Starting the Program**: 
   - The program starts with a welcome message and an "Offline" status.
   
2. **User Authentication**:
   - The program prompts you to enter your password.
   - If the login credentials are valid, the status changes to "Online" and displays your username.

3. **Chat Messages**:
   - Enter a message and press `Enter` to send it.
   - Messages are encrypted before being saved and displayed.
   - Enter `!clear` to clear the chat or `exit` to quit the program.

4. **File Monitoring**:
   - The program monitors the JSON file for changes and updates the display automatically.

## Code Structure

- **`Program.cs`**: Main program containing logic for user authentication, message storage, and display.
- **`ChatMessage` Class**: Represents a chat message with username, timestamp, and text.

## Detailed Functions

- **`Main`**: Starts the program, checks the JSON file version, prompts for login, and starts the chat.
- **`LoadJsonVersion`**: Loads and checks the version of the JSON file.
- **`ValidateUser`**: Validates a user's login credentials.
- **`LoadMessages`**: Loads messages from the JSON file and decrypts them.
- **`DisplayChat`**: Shows the chat and allows sending messages.
- **`DisplayMessages`**: Displays all messages in the chat.
- **`ClearChat`**: Clears all messages in the chat and saves the empty state.
- **`SaveMessage`**: Saves an encrypted message to the JSON file.
- **`OnJsonChanged`**: Responds to changes in the JSON file and updates the chat.
- **`Encrypt` / `Decrypt`**: Encrypts and decrypts messages using AES.
- **`ComputeSha256Hash`**: Computes the SHA-256 hash for passwords and usernames.
- **`LoadUsers`**: Loads user data from the JSON file.
- **`SaveUser`**: Saves user data and status to the JSON file.
- **`ReadPassword`**: Securely reads the password from the console.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

For questions or issues, please contact [your contact address].


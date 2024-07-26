using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Newtonsoft.Json;

class Program
{
    static string jsonFilePath = @"\\brudehsm\austausch\dhaenic\test.json";
    static string userName;
    static string passwordHash;
    static List<ChatMessage> messages = new List<ChatMessage>();
    static readonly object messageLock = new object();
    static bool isRunning = true;
    static FileSystemWatcher watcher;

    static void Main(string[] args)
    {
        Console.Clear();
        Console.Title = "Chat - Status: Offline - Benutzer: - Online: 0";

        Console.WriteLine("Willkommen beim verschlüsselten Chat!");


        int jsonVersion = 1;
        int currentVersion = LoadJsonVersion();
        if (jsonVersion != currentVersion)
        {
            Console.WriteLine($"Die JSON-Datei hat eine andere Version ({currentVersion}).");
            Console.WriteLine("Bitte kontaktiere den Administrator für die aktuelle Version.");
            Console.WriteLine("Drücke eine beliebige Taste, um das Programm zu beenden.");
            Console.ReadKey();
            return;
        }

        userName = Environment.UserName;
        Console.WriteLine($"Automatisch eingestellter Benutzername: {userName}");

        Console.Write("Gib dein Passwort ein: ");
        string password = ReadPassword();
        passwordHash = ComputeSha256Hash(password);

        if (ValidateUser(userName, passwordHash))
        {
            Console.Clear();
            Console.Title = $"Chat - Status: Online - Benutzer: {userName}";
            Console.WriteLine("Login erfolgreich.");

            LoadMessages();

            watcher = new FileSystemWatcher
            {
                Path = Path.GetDirectoryName(jsonFilePath),
                Filter = Path.GetFileName(jsonFilePath),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName
            };
            watcher.Changed += OnJsonChanged;
            watcher.Created += OnJsonChanged;
            watcher.Deleted += OnJsonChanged;
            watcher.EnableRaisingEvents = true;

            DisplayChat();
        }
        else
        {
            Console.Beep(); 
            Console.WriteLine("Ungültiges Passwort.");
            Console.WriteLine("Drücke eine beliebige Taste, um das Programm zu beenden.");
            Console.ReadKey();
        }
    }

    static int LoadJsonVersion()
    {
        if (File.Exists(jsonFilePath))
        {
            string json = File.ReadAllText(jsonFilePath);
            var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
            if (jsonData.ContainsKey("version"))
            {
                return Convert.ToInt32(jsonData["version"]);
            }
        }
        return -1; 
    }

    static bool ValidateUser(string username, string passwordHash)
    {
        string hashedUsername = ComputeSha256Hash(username);

        if (File.Exists(jsonFilePath))
        {
            string json = File.ReadAllText(jsonFilePath);
            var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
            if (jsonData.ContainsKey("users"))
            {
                var users = JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(jsonData["users"].ToString());
                foreach (var user in users)
                {
                    if (user["username"].ToString() == hashedUsername)
                    {
                        if (user.ContainsKey("banned") && Convert.ToBoolean(user["banned"]))
                        {
                            string expiresAtStr = user["banExpiresAt"].ToString();
                            if (expiresAtStr == "false")
                            {
                                Console.WriteLine("Dein Benutzername ist permanent gesperrt.");
                                return false;
                            }
                            else if (DateTime.TryParse(expiresAtStr, out DateTime expiresAt))
                            {
                                if (DateTime.UtcNow < expiresAt)
                                {
                                    Console.WriteLine($"Dein Benutzername ist bis {expiresAt} gesperrt.");
                                    return false;
                                }
                            }
                        }
                        return user["password"].ToString() == passwordHash;
                    }
                }
            }
        }
        return false;
    }

    static void LoadMessages()
    {
        lock (messageLock)
        {
            messages.Clear();
            if (File.Exists(jsonFilePath))
            {
                string json = File.ReadAllText(jsonFilePath);
                var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                if (jsonData.ContainsKey("messages"))
                {
                    var encryptedMessages = JsonConvert.DeserializeObject<List<string>>(jsonData["messages"].ToString());
                    foreach (var encryptedMessage in encryptedMessages)
                    {
                        string decryptedMessage = Decrypt(encryptedMessage, passwordHash);
                        var messageParts = decryptedMessage.Split(new[] { "::" }, StringSplitOptions.None);
                        if (messageParts.Length == 3)
                        {
                            var username = messageParts[0];
                            var timestamp = messageParts[1];
                            var messageText = messageParts[2];
                            messages.Add(new ChatMessage(username, timestamp, messageText));
                        }
                    }
                }
            }
        }
    }

    static void DisplayChat()
    {
        while (isRunning)
        {
            Console.Clear();
            DisplayMessages();
            Console.WriteLine("=================");
            Console.WriteLine("Gib eine Nachricht ein (oder 'exit' zum Beenden, '!clear' zum Löschen):");
            string input = Console.ReadLine();
            if (input.ToLower() == "exit")
            {
                isRunning = false;
                break;
            }
            else if (input.ToLower() == "!clear")
            {
                ClearChat();
            }
            else
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                var messageToSave = $"{userName}::{timestamp}::{input}";
                var encryptedMessage = Encrypt(messageToSave, passwordHash);
                SaveMessage(encryptedMessage);

                Thread.Sleep(1000);
            }
        }
    }

    static void DisplayMessages()
    {
        lock (messageLock)
        {
            Console.WriteLine("===== CHAT =====");
            if (messages.Count == 0)
            {
                Console.WriteLine("Keine Nachrichten vorhanden.");
            }
            else
            {
                foreach (var message in messages)
                {
                    Console.WriteLine($"[{message.Username}] - {message.Timestamp}: {message.Text}");
                }
            }
        }
    }

    static void ClearChat()
    {
        lock (messageLock)
        {
            if (File.Exists(jsonFilePath))
            {
                File.WriteAllText(jsonFilePath, JsonConvert.SerializeObject(new
                {
                    version = LoadJsonVersion(),
                    messages = new List<string>(),
                    users = LoadUsers(),
                }, Formatting.Indented));

                messages.Clear();

                Console.WriteLine("Der Chat wurde gelöscht.");
                Console.WriteLine("Drücke eine beliebige Taste, um fortzufahren...");
                Console.ReadKey();
            }
        }
    }

    static void SaveMessage(string encryptedMessage)
    {
        lock (messageLock)
        {
            if (File.Exists(jsonFilePath))
            {
                string json = File.ReadAllText(jsonFilePath);
                var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                var currentMessages = jsonData.ContainsKey("messages")
                    ? JsonConvert.DeserializeObject<List<string>>(jsonData["messages"].ToString())
                    : new List<string>();

                currentMessages.Add(encryptedMessage);

                jsonData["messages"] = currentMessages;

                File.WriteAllText(jsonFilePath, JsonConvert.SerializeObject(jsonData, Formatting.Indented));
            }
        }
    }

    static void OnJsonChanged(object sender, FileSystemEventArgs e)
    {
        Thread.Sleep(100); 

        LoadMessages();
        DisplayMessages();
    }

    static string ComputeSha256Hash(string rawData)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            StringBuilder builder = new StringBuilder();
            foreach (byte b in bytes)
            {
                builder.Append(b.ToString("x2"));
            }
            return builder.ToString();
        }
    }

    static string Encrypt(string plainText, string key)
    {
        byte[] keyBytes = new byte[32];
        byte[] keyInput = Encoding.UTF8.GetBytes(key);

        Array.Copy(keyInput, keyBytes, Math.Min(keyInput.Length, keyBytes.Length));

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.GenerateIV();

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    byte[] iv = aesAlg.IV;
                    byte[] encrypted = msEncrypt.ToArray();

                    byte[] result = new byte[iv.Length + encrypted.Length];
                    Array.Copy(iv, 0, result, 0, iv.Length);
                    Array.Copy(encrypted, 0, result, iv.Length, encrypted.Length);
                    return Convert.ToBase64String(result);
                }
            }
        }
    }

    static string Decrypt(string cipherText, string key)
    {
        byte[] keyBytes = new byte[32];
        byte[] keyInput = Encoding.UTF8.GetBytes(key);

        Array.Copy(keyInput, keyBytes, Math.Min(keyInput.Length, keyBytes.Length));

        byte[] fullCipher = Convert.FromBase64String(cipherText);
        byte[] iv = new byte[16];
        byte[] cipher = new byte[fullCipher.Length - iv.Length];

        Array.Copy(fullCipher, 0, iv, 0, iv.Length);
        Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.IV = iv;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipher))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    static List<Dictionary<string, object>> LoadUsers()
    {
        if (File.Exists(jsonFilePath))
        {
            string json = File.ReadAllText(jsonFilePath);
            var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
            if (jsonData.ContainsKey("users"))
            {
                return JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(jsonData["users"].ToString());
            }
        }
        return new List<Dictionary<string, object>>();
    }

    static void SaveUser(string username, string passwordHash, bool banned, DateTime? banExpiresAt)
    {
        lock (messageLock)
        {
            if (File.Exists(jsonFilePath))
            {
                string json = File.ReadAllText(jsonFilePath);
                var jsonData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                var users = jsonData.ContainsKey("users")
                    ? JsonConvert.DeserializeObject<List<Dictionary<string, object>>>(jsonData["users"].ToString())
                    : new List<Dictionary<string, object>>();

                var user = users.Find(u => u["username"].ToString() == ComputeSha256Hash(username));
                if (user != null)
                {
                    user["password"] = passwordHash;
                    user["banned"] = banned;
                    user["banExpiresAt"] = banExpiresAt?.ToString() ?? "false";
                }
                else
                {
                    users.Add(new Dictionary<string, object>
                    {
                        ["username"] = ComputeSha256Hash(username),
                        ["password"] = passwordHash,
                        ["banned"] = banned,
                        ["banExpiresAt"] = banExpiresAt?.ToString() ?? "false"
                    });
                }

                jsonData["users"] = users;

                File.WriteAllText(jsonFilePath, JsonConvert.SerializeObject(jsonData, Formatting.Indented));
            }
        }
    }

    static string ReadPassword()
    {
        StringBuilder password = new StringBuilder();
        ConsoleKeyInfo key;
        do
        {
            key = Console.ReadKey(intercept: true);
            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        } while (key.Key != ConsoleKey.Enter);
        Console.WriteLine();
        return password.ToString();
    }
}

class ChatMessage
{
    public string Username { get; }
    public string Timestamp { get; }
    public string Text { get; }

    public ChatMessage(string username, string timestamp, string text)
    {
        Username = username;
        Timestamp = timestamp;
        Text = text;
    }
}

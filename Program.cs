using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using System.IO;
using System.Dynamic;

namespace VaultGarden // Note: actual namespace depends on the project name.
{
    class Program
    {
        public static int filesRepaired = 0;
        public static int dirRepaired = 0;
        public static string user_pass = "";
        public static string dataFolderName = "VaultGarden Data";
        public static string appDataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), dataFolderName);

        public static string userPassTextFileLocationPC = Path.Combine(appDataFolderPath, "Data", "Passwords", "user_pass.txt");
        public static string userPassSaltTextFileLocationPC = Path.Combine(appDataFolderPath, "Data", "Passwords", "salt.txt");

        public static string userPassTextFileLocationUSB = "";
        public static string userPassSaltTextFileLocationUSB = "";

        public static bool needsNewPass;
        public static string usbPath = "";
        public static bool installedOnUSB;
        public static string installUSBDrivePath = ""; // ex. F:/

        public const int keySize = 64;
        public const int iterations = 350000;
        public static HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

        public static string appVersion = "Version name not determined";

        public static void Main()
        {
            Console.Title = "VaultGarden - " + appVersion;
            Console.WriteLine("Starting setup...\n");

            // Check if program has already finished setup
            bool setupIsDone = SetupIsDone();
            if (!setupIsDone)
            {
                string installOnUSB = null;

                // Asking if user wants to install data folder on USB or not

                while (string.IsNullOrEmpty(installOnUSB) || (installOnUSB != "y" && installOnUSB != "n"))
                {
                    Console.WriteLine("Install on USB? [y/n]");
                    installOnUSB = Console.ReadLine();

                    if (string.IsNullOrEmpty(installOnUSB) || (installOnUSB != "y" && installOnUSB != "n"))
                    {
                        Console.WriteLine("Invalid input. Please enter 'y' or 'n'.");
                    }
                }

                if (installOnUSB == "y")
                {
                    installedOnUSB = true;
                    while (true)
                    {
                        List<USBDeviceInfo> usbDevices = GetUSBStorageDevices();

                        if (usbDevices.Count == 0)
                        {
                            ClrConsole();
                            Console.WriteLine("No USB devices detected.");
                            Console.WriteLine("Press enter to search again...");
                            Console.ReadLine();
                        }
                        else
                        {
                            Console.WriteLine("USB devices:");

                            for (int i = 0; i < usbDevices.Count; i++)
                            {
                                Console.WriteLine($"[{i + 1}] {usbDevices[i].Description}");
                            }

                            Console.WriteLine("Select a USB device:");
                            string userInput = Console.ReadLine();

                            if (int.TryParse(userInput, out int selectedIndex) && selectedIndex > 0 && selectedIndex <= usbDevices.Count)
                            {
                                usbPath = usbDevices[selectedIndex - 1].DriveLetter + "\\";

                                // Save the path for the password hash writing function. 
                                userPassTextFileLocationUSB = usbPath + "\\"; // Ex. "F:\\"

                                // Save the drive letter to a global variable
                                installUSBDrivePath = userPassTextFileLocationUSB;

                                string driveLetter = usbPath;

                                // Correct path for user password in a USB drive.
                                userPassTextFileLocationUSB = Path.Combine(userPassTextFileLocationUSB, dataFolderName, "Data", "Passwords", "user_pass.txt");

                                Console.WriteLine("Program is saving the hash to this path: " + userPassTextFileLocationUSB);
                                Console.ReadLine();

                                Console.WriteLine($"Selected USB device: {usbDevices[selectedIndex - 1].Description}");
                                GenerateFileStructure(true, usbPath);

                                userPassTextFileLocationUSB = usbPath + "\\";
                                // Path to save drive letter
                                string usbDriveLetterLocation = Path.Combine(userPassTextFileLocationUSB, dataFolderName, "Data", "Settings", "usb_drive.txt");

                                // Saving the drive letter to a text file for future functionality
                                SaveUSBLetter(usbDriveLetterLocation, driveLetter);
                                userPassTextFileLocationUSB = Path.Combine(userPassTextFileLocationUSB, dataFolderName, "Data", "Passwords", "user_pass.txt");
                                userPassSaltTextFileLocationUSB = Path.Combine(userPassTextFileLocationUSB, dataFolderName, "Data", "Passwords", "salt.txt");
                            }
                            else
                            {
                                Console.WriteLine("Invalid selection. Please try again.");
                            }


                            break;
                        }
                    }
                }

                else if (installOnUSB == "n")
                {
                    installedOnUSB = false;
                    GenerateFileStructure(false, "");
                }

                filesRepaired.ToString();
                dirRepaired.ToString();
            }

            // Data folder exists but could be broken, run repairs
            (bool onUSB, string USBPath) = HasUSBInstall();
            if (onUSB)
            {
                // Save the drive letter to a global variable
                installUSBDrivePath = usbPath + "\\";
                Console.WriteLine("Global usb path saved: " + installUSBDrivePath);

                GenerateFileStructure(true, usbPath);
            }
            GenerateFileStructure(false, "");

            if (needsNewPass)
            {
                Console.WriteLine("Choose a SECURE password for VaultGarden (store this pass in a safe location or preferably, in your head):");
                user_pass = SecurePass(15, true, true);

                Console.WriteLine($"\nSetup finished, {filesRepaired} {(filesRepaired == 1 ? "file" : "files")} and {dirRepaired} {(dirRepaired == 1 ? "directory" : "directories")} {(dirRepaired == 1 ? "was" : "were")} repaired.\nUser password is: " + user_pass);
                Console.WriteLine("\nHashing password and storing it in a text file...");
                string hashedPassword = HashPassword(user_pass, out var salt);
                Console.WriteLine("\nPassword hash: " + hashedPassword);
                Console.WriteLine($"Generated salt: {Convert.ToHexString(salt)}");
                WriteHashedPasswordToFiles(hashedPassword, Convert.ToHexString(salt), installedOnUSB);
                Console.WriteLine("\nPress enter to finish setup!");
                Console.ReadLine();
            }

            // User_pass already exists or user chose a password, login 
            Login();

            // Go to home
            Home();

        }

        public static string SecurePass(int minChar, bool needsHigherCase, bool needsNumbers)
        {
            string user_pass = GetMaskedInput();

            while (string.IsNullOrWhiteSpace(user_pass) || user_pass.Length < minChar || (needsHigherCase && !HasUppercaseCharacter(user_pass)) || (needsNumbers && !HasNumberCharacter(user_pass)))
            {
                if (string.IsNullOrWhiteSpace(user_pass))
                {
                    Console.WriteLine("Password cannot be empty. Please enter a valid password:");
                }
                else if (user_pass.Length < minChar)
                {
                    Console.WriteLine($"Password should have at least {minChar} characters. Please enter a valid password:");
                }
                else if (needsHigherCase && !HasUppercaseCharacter(user_pass))
                {
                    Console.WriteLine("Password should contain at least one uppercase character. Please enter a valid password:");
                }
                else if (needsNumbers && !HasNumberCharacter(user_pass))
                {
                    Console.WriteLine("Password should contain at least one number. Please enter a valid password:");
                }

                user_pass = GetMaskedInput();
            }

            Console.WriteLine("Repeat password:");
            string user_pass_repeat = GetMaskedInput();

            while (string.IsNullOrWhiteSpace(user_pass_repeat) || user_pass != user_pass_repeat)
            {
                if (string.IsNullOrWhiteSpace(user_pass_repeat))
                {
                    Console.WriteLine("Password cannot be empty. Please enter a valid password:");
                }
                else
                {
                    Console.WriteLine("Passwords don't match. Please try again:");
                }

                user_pass_repeat = GetMaskedInput();
            }

            // Both passwords match
            return user_pass;
        }

        public static bool HasUppercaseCharacter(string password)
        {
            foreach (char c in password)
            {
                if (char.IsUpper(c))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool HasNumberCharacter(string password)
        {
            foreach (char c in password)
            {
                if (char.IsDigit(c))
                {
                    return true;
                }
            }

            return false;
        }

        public static void CreateDirectoryIfMissing(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
                dirRepaired++;
            }
        }

        public static void CreateFileIfMissing(string filePath)
        {
            if (!File.Exists(filePath))
            {
                File.Create(filePath).Dispose();
                filesRepaired++;
            }
        }

        public static bool IsDirEmpty(string directoryPath)
        {
            string filePath = Path.Combine(directoryPath, "user_pass.txt");

            // Gotta tackle validation here sooner, users with malicious intents could just create their own user_pass.txt.

            return !File.Exists(filePath);
        }

        private static string GetMaskedInput()
        {
            string input = "";
            ConsoleKeyInfo keyInfo;

            do
            {
                keyInfo = Console.ReadKey(true);

                // Ignore any non-character keys
                if (keyInfo.Key != ConsoleKey.Backspace && keyInfo.Key != ConsoleKey.Enter)
                {
                    input += keyInfo.KeyChar;
                    Console.Write("*"); // Print a mask character instead of the actual input
                }
                else if (keyInfo.Key == ConsoleKey.Backspace && input.Length > 0)
                {
                    // Handle backspace by removing the last character from the input
                    input = input.Remove(input.Length - 1);
                    Console.Write("\b \b"); // Move the cursor back, erase the character, and move the cursor back again
                }
            }
            while (keyInfo.Key != ConsoleKey.Enter);

            Console.WriteLine(); // Move to the next line after the user presses Enter
            return input;
        }

        public static void GenerateFileStructure(bool USB, string USBpath)
        {
            if (USB)
            {

                // Get directories in usb
                List<string> directories = GetDirectories(USBpath);

                if (directories.Count == 0)
                {
                    Console.WriteLine("\nNo directories found in the specified USB path.");
                    Console.WriteLine("Press enter to search again...");
                    Console.ReadLine();
                }

                Console.WriteLine("The app will be installed to root. Confirm? [y/n]");
                string installConfirmation = Console.ReadLine();

                while (installConfirmation.ToLower() != "y" && installConfirmation.ToLower() != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'y' to confirm or 'n' to cancel:");
                    installConfirmation = Console.ReadLine();
                }

                if (installConfirmation.ToLower() == "y")
                {
                    // Proceed with the installation to the root directory
                    USBpath = USBpath + "/" + dataFolderName;
                    // Installation will occur on a USB stick. Will be installed to root. 
                    CreateDirectoryIfMissing(Path.Combine(USBpath, "Data", "Passwords"));
                    CreateDirectoryIfMissing(Path.Combine(USBpath, "Data", "Settings"));
                    CreateDirectoryIfMissing(Path.Combine(USBpath, "Logs"));

                    // Create files if they don't exist
                    CreateFileIfMissing(Path.Combine(USBpath, "Data", "Settings", "config.ini"));
                    CreateFileIfMissing(Path.Combine(USBpath, "Logs", "error.log"));
                    CreateFileIfMissing(Path.Combine(USBpath, "Logs", "access.log"));

                    // Check if passwords directory is empty with isDirEmpty()
                    needsNewPass = IsDirEmpty(Path.Combine(USBpath, "Data", "Passwords"));
                }
                else
                {
                    // Cancel the installation
                    // Provide appropriate feedback or perform any necessary cleanup
                    Console.WriteLine("Installation canceled, press enter to close...");
                    Console.ReadLine();
                }

            }
            else
            {
                // User wants files on the pc, not on USB. File structure is installed in the appdata folder
                // Create directories if they don't exist
                CreateDirectoryIfMissing(Path.Combine(appDataFolderPath, "Data", "Passwords"));
                CreateDirectoryIfMissing(Path.Combine(appDataFolderPath, "Data", "Settings"));
                CreateDirectoryIfMissing(Path.Combine(appDataFolderPath, "Logs"));

                // Create files if they don't exist
                CreateFileIfMissing(Path.Combine(appDataFolderPath, "Data", "Settings", "config.ini"));
                CreateFileIfMissing(Path.Combine(appDataFolderPath, "Logs", "error.log"));
                CreateFileIfMissing(Path.Combine(appDataFolderPath, "Logs", "access.log"));

                // Check if passwords directory is empty with isDirEmpty()
                needsNewPass = IsDirEmpty(Path.Combine(appDataFolderPath, "Data", "Passwords"));
            }
        }

        public static string HashPassword(string password, out byte[] salt)
        {
            salt = RandomNumberGenerator.GetBytes(keySize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                hashAlgorithm,
                keySize);
            return Convert.ToHexString(hash);
        }

        static List<USBDeviceInfo> GetUSBStorageDevices()
        {
            List<USBDeviceInfo> devices = new List<USBDeviceInfo>();

            using var searcher = new ManagementObjectSearcher(
                @"Select * From Win32_DiskDrive WHERE InterfaceType='USB'");
            using ManagementObjectCollection collection = searcher.Get();

            foreach (var device in collection)
            {
                string deviceId = (string)device.GetPropertyValue("DeviceID");
                string description = (string)device.GetPropertyValue("Description");

                // Get drive letter
                ManagementObject partition = new ManagementObjectSearcher(
                    "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + deviceId + "'} WHERE AssocClass = Win32_DiskDriveToDiskPartition").Get().OfType<ManagementObject>().FirstOrDefault();
                if (partition != null)
                {
                    ManagementObject logicalDisk = new ManagementObjectSearcher(
                        "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + partition["DeviceID"] + "'} WHERE AssocClass = Win32_LogicalDiskToPartition").Get().OfType<ManagementObject>().FirstOrDefault();
                    if (logicalDisk != null)
                    {
                        string driveLetter = (string)logicalDisk["DeviceID"];
                        devices.Add(new USBDeviceInfo(deviceId, driveLetter, description));
                    }
                }
            }

            return devices;
        }

        static List<string> GetDirectories(string path)
        {
            List<string> directories = new List<string>();

            try
            {
                directories = Directory.GetDirectories(path).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred while accessing the USB drive: {ex.Message}");
            }

            return directories;
        }

        public static void WriteHashedPasswordToFiles(string hashedPassword, string salt, bool onUSB)
        {
            // Write hash and salt to files
            if (onUSB)
            {
                File.WriteAllText(userPassTextFileLocationUSB, hashedPassword);
                File.WriteAllText(userPassSaltTextFileLocationUSB, salt);

            }
            else
            {
                File.WriteAllText(userPassTextFileLocationPC, hashedPassword);
                File.WriteAllText(userPassSaltTextFileLocationPC, salt);
            }
        }

        public static void SaveUSBLetter(string path, string USBLetter)
        {
            try
            {
                File.WriteAllText(path, USBLetter);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error Occurred: " + e.Message);
            }
        }

        // Function to check if data folder already has been created in a USB drive or 
        public static bool SetupIsDone()
        {
            // Check if the executable exists in a USB drive or a normal PC drive
            (bool isUSB, string drive) = HasUSBInstall();
            if (isUSB)
            {
                string dataFolderPath = Path.Combine(drive, dataFolderName);
                if (Directory.Exists(dataFolderPath))
                {
                    // Directory exists on USB drive
                    return true;
                }
                else
                {
                    // Directory does not exist on USB drive
                    return false;
                }
            }
            else
            {
                string dataFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), dataFolderName);
                if (Directory.Exists(dataFolderPath))
                {
                    // Directory exists on PC drive
                    return true;
                }
                else
                {
                    // Directory does not exist on PC drive
                    return false;
                }
            }
        }

        // Function to check if the app is installed on USB or not.
        public static (bool, string) HasUSBInstall()
        {
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            string installationDrive = Path.GetPathRoot(assemblyLocation);

            DriveInfo driveInfo = new DriveInfo(installationDrive);
            bool isUSBDrive = driveInfo.DriveType == DriveType.Removable;

            return (isUSBDrive, installationDrive);
        }

        public static void ClrConsole()
        {
            Console.Clear();
        }

        private static string ReadInput()
        {
            string input = "";
            bool isValidInput = false;

            while (!isValidInput)
            {
                try
                {
                    input = Console.ReadLine();
                    isValidInput = true;
                }
                catch (IOException)
                {
                    Console.WriteLine("\nAn error occurred while reading the input. Please try again.\n");
                }
            }

            return input;
        }

        private static void WriteVersionHeader()
        {
            Console.WriteLine("================= VaultGarden - " + appVersion + " =================\n");
        }


        public static void Login()
        {
            ClrConsole();
            WriteVersionHeader();

            // TODO: Implement logic to detect if installation is on usb or pc. Maybe a function that returns a bool? HasUSBInstall()
            (bool isUSB, string drive) = HasUSBInstall();
            if (isUSB)
            {
                Console.WriteLine("USB install detected.\n\n");
            }

            else
            {
                Console.WriteLine("Non-USB install detected.\n\n");
            }

            // Below code just works on PC
            // PC ONLY

            Console.WriteLine("Password: ");
            Console.WriteLine("\n\nDont remember? Delete the data folder.");
            string password = GetMaskedInput();

            // Hash the input
            string hashedPassword = HashPassword(password, out var salt);

            // Get saved hash from files from pc appdata
            string savedHashedPassword = File.ReadAllText(userPassTextFileLocationPC);

            // Get saved salt from the files
            string savedSalt = File.ReadAllText(userPassSaltTextFileLocationPC);

            // Verify the password
            bool passwordIsCorrect = VerifyPassword(savedHashedPassword, hashedPassword, savedSalt);

            if (passwordIsCorrect)
            {
                Home();
            }
            else
            {
                Console.WriteLine("Incorrect.");
                // Wait some seconds before exiting
                Environment.Exit(0);
            }
        }

        public static bool VerifyPassword(string password, string hash, byte[] salt)
        {
            var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
            return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
        }

        // Function to display passwords
        private static void DisplayPasswords()
        {
            // Code to display passwords
            WriteVersionHeader();
            Console.WriteLine("PASSWORDS:");

            // Retrive password data from the password folder. USB path is saved in installUSBDrivePath
        }

        // Function to create a new password
        private static void CreatePassword()
        {
            // Code to create a new password
            WriteVersionHeader();

            // User should input application name, email address for the application, username for the application and a password for the application. Also additional notes. 

        }

        public static void Home()
        {
            ClrConsole();
            WriteVersionHeader();
            Console.WriteLine("[M] -- [C]"); // Manage and Create passwords
            string input = ReadInput();

            if (input.ToLower() == "m")
            {
                // Display passwords
                DisplayPasswords();
            }

            else if (input.ToLower() == "c")
            {
                // Create a new password
                CreatePassword();
            }
        }
    }

    class USBDeviceInfo
    {
        public string DeviceID { get; }
        public string DriveLetter { get; }
        public string Description { get; }

        public USBDeviceInfo(string deviceID, string driveLetter, string description)
        {
            DeviceID = deviceID;
            DriveLetter = driveLetter;
            Description = description;
        }
    }
}
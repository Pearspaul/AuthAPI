namespace AuthAPI.Helpers
{
    public class Constants
    {
        public const string SecurityCode = "...jwtSecureCode...";
        public const string SqlConnectionString = "SqlServerConnStr";
        public const string EmailRegex = "[<,>,!,@,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,,.,/,~,`,-,=]";
        public const string UserId = "UserId";
        public const string AdminEmail = "AdminEmail";
        public const string UserNotFound = "User Not Found!";
        public const string PasswordIncorrect = "Password is Incorrect!";
        public const string UserExist = "Username Already Exist!";
        public const string EmailExist = "Email Already Exist!";
        public const string UserRole = "User";
        public const string AdminRole = "Admin";
        public const string UserRegistered = "User Registered!";
        public const string InvalidRequest = "Invalid Client Request";
        public const string MinPasswordlength = "Minimum password length should be 8";
        public const string AlphanumericPassword = "Password should be Alphanumeric";
        public const string SpecialCharPassword = "Password should contain special chars";
        public const string InvalidToken = "This is invalied Token";

    }
}

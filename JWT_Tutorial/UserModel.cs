namespace JWT_Tutorial
{
    public class UserModel
    {

        public string Username { get; set; } = String.Empty;

        public byte[] PasswordHash { get; set; }

        public byte[] PasswordSalt { get; set; }
    }
}

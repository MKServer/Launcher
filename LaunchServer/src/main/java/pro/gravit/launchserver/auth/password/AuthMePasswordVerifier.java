package pro.gravit.launchserver.auth.password;

import pro.gravit.utils.helper.IOHelper;

import java.security.MessageDigest;
import java.util.Base64;

public class AuthMePasswordVerifier extends PasswordVerifier {

    private static final String DELIMITER = "\\$";

    @Override
    // $SHA$salt$hash, where hash = sha256(sha256(password) . salt)
    public boolean check (String encryptedPassword, String password) {
        String[] parts = encryptedPassword.split(DELIMITER);

        return parts.length == 4 && parts[3].equalsIgnoreCase(
                hash(hash(password).concat(parts[2]))
        );
    }

    private String hash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(IOHelper.encode(text));

            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception ignored) {
            return "";
        }
    }
}

package burp;
import java.util.ArrayList;
import java.util.List;

public class MatchChecker {

    public List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helper) {
        List<int[]> matches = new ArrayList<>();
        int start = 0;
        int resLen = response.length;
        int matchLen = match.length;

        while (start < resLen) {
            start = helper.indexOf(response, match, true, start, resLen);
            if (start == -1) {
                break;
            }
            int[] matchIndices = { start, start + matchLen };
            matches.add(matchIndices);
            start += matchLen;
        }

        return matches;
    }
}


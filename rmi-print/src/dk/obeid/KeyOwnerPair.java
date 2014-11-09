package dk.obeid;

import java.security.PublicKey;

public class KeyOwnerPair {
    private PublicKey pub;
    private String owner;

    public KeyOwnerPair(PublicKey p, String o){
        pub = p;
        owner = o;
    }

    public String getOwner() {
        return owner;
    }

    public PublicKey getPub() {
        return pub;
    }
}
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalTime;

public class DroneKE {

    static BigInteger MSK, k, n, PIDs;
    static String IDs;

    static String IDi, PWi;
    static BigInteger PIDi, alphai;
    static BigInteger PIDim, alphaim;

    static String IDj;
    static BigInteger PIDj, alphaj;

    static SecureRandom rnd = new SecureRandom();
    
    static String[][] Ls = new String[2][3]; 

    
    public static void main(String[] args) throws Exception {
        
        // CS Setup Phase
            System.out.println("\n--- CS Setup Phase ---");
            //CS chooses 160 bit MSK and k 
            MSK = new BigInteger(160, rnd); 
            k = new BigInteger(160, rnd);
            
            //CS chooses public system parameter
            n = BigInteger.probablePrime(300, rnd);
            
            //CS sets its identity IDs
            BigInteger nsid = new BigInteger(16,rnd);
            IDs = "serverID"+nsid.toString();
            System.out.println("IDs = "+IDs);
            
            //CS computes PIDs
            PIDs = Hash(IDs+k.toString());

            //Print the Secret and Public Key in HEX
            System.out.println("Secret Key (HEX)");
            System.out.println("MSK = "+MSK.toString(16));
            System.out.println("k = "+k.toString(16));

            System.out.println("\nPublic Key (HEX)");
            System.out.println("h : using SHA-256");
            System.out.println("n = "+n.toString(16));
            System.out.println("PIDs = "+PIDs.toString(16));

        //Drone Registration Phase
            System.out.println("\n--- Drone Registration Phase ---");
            //Drone sets its identity IDj
            BigInteger droneid = new BigInteger(16,rnd);
            IDj = "droneID"+droneid.toString();
            System.out.println("IDj = "+IDj);
            
            //CS computes PIDj and alpha_j for Drone
            PIDj = Hash(IDj+k.toString());
            alphaj = Hash(IDj+MSK.toString());
            System.out.println("PIDj and alpha_j from CS (HEX)");
            System.out.println("PIDj = "+PIDj.toString(16));
            System.out.println("alpha_j = "+alphaj.toString(16));
            
            //CS stores (IDj, alpha_j, PIDj) in Ls
            Ls[0][0] = IDj;
            Ls[0][1] = alphaj.toString();
            Ls[0][2] = PIDj.toString();
        
        //User Registration Phase
            System.out.println("\n--- User Registration Phase ---");
            
            //User sets its identity IDi and Password PWi
            BigInteger usid = new BigInteger(16,rnd);
            IDi = "userID"+usid.toString();
            System.out.println("IDi = "+IDi);

            BigInteger pwi = new BigInteger(40,rnd);
            PWi = "user"+pwi.toString(16);
            System.out.println("PWi = "+PWi);

            //CS computes PIDi and alpha_i for User
            PIDi = Hash(IDi+k.toString());
            alphai = Hash(IDi+MSK.toString());
            System.out.println("\nPIDi and alpha_i from CS (HEX)");
            System.out.println("PIDi = "+PIDi.toString(16));
            System.out.println("alpha_i = "+alphai.toString(16));

            //CS stores (IDi, alpha_i, PIDi) in Ls
            Ls[1][0] = IDi;
            Ls[1][1] = alphai.toString();
            Ls[1][2] = PIDi.toString();

            //User alpha^m_i and PID^m_i
            BigInteger tmp = Hash(IDi+PWi);
            alphaim = tmp.xor(alphai);
            PIDim = tmp.xor(PIDi);
            System.out.println("\nUser PID^m_i and alpha_m_i (HEX)");
            System.out.println("PID^m_i = "+PIDim.toString(16));
            System.out.println("alpha^m_i = "+alphaim.toString(16));

        
        // Authentication Phase
            System.out.println("\n--- Authentication Phase ---");
        
        //---4.4.(1)
            //User Ui computes PIDi and alpha_i        
            BigInteger z = Hash(IDi+PWi);
            PIDi = PIDim.xor(z); 
            alphai = alphaim.xor(z);

            //User Ui chooses 160 bits r1
            BigInteger r1 = new BigInteger(160,rnd);
            //User Ui sets current timestamp ST1
            LocalTime ST1 = LocalTime.now(); 
            System.out.println("Current time stamp ST1 = "+ST1); 
            
            //User Ui computes M1,M2,M3,M4
            BigInteger M1,M2,M3,M4;
            M1 = Hash(PIDs.toString()+ST1.toString()).xor(PIDi);
            M2 = Hash(PIDi.toString()+PIDs.toString()+alphai.toString()).xor(r1);
            M3 = Hash(PIDi.toString()+PIDs.toString()+alphai.toString()+r1.toString()).xor(PIDj);
            M4 = Hash(PIDi.toString()+PIDj.toString()+PIDs.toString()+alphai.toString()+r1.toString());

        //---4.4.(2)
            BigInteger PIDip, alphaip, r1p, PIDjp, M4p;
            
            //CS check the validation of time
            long timeThreshold = 3; //maximum time threshold
            System.out.println("CS checks validation time");
            System.out.println("Max time threshold deltaT = "+timeThreshold+" second");
            LocalTime time = LocalTime.now();
            System.out.println("Time Now = "+time);
            Duration dT = Duration.between(ST1, time); // compute time-ST1
            
            long deltaT = dT.getSeconds();
            
            //Check if deltaT > timeThreshold
            if (deltaT>timeThreshold) {
                System.out.println("CS rejects the authentication request");
                return;
            } else {
                System.out.println("CS accepts the messages");
            }

            //CS computes PID'i            
            PIDip = M1.xor(Hash(PIDs.toString()+ST1.toString()));

            //CS retrieves a'i from PID'i in Ls
            alphaip = getAlpha(PIDip, Ls);
            //If the a'_i = 0 then PID'_i is not valid 
            if (alphaip.toString()=="0") {
                System.out.println("The identity PIDi' is not found in Ls");
                return;
            }
            
            //CS computes r1', PIDj', M4'
            r1p = M2.xor(Hash(PIDip.toString()+PIDs.toString()+alphaip.toString()));
            PIDjp = M3.xor(Hash(PIDi.toString()+PIDs.toString()+alphaip.toString()+r1p.toString()));
            M4p = Hash(PIDi.toString()+PIDjp.toString()+PIDs.toString()+alphaip.toString()+r1p.toString());

        //---4.4.(3)
            //CS checks M4 = M4'
            System.out.println("\nCS checks for M4");
            if (M4.equals(M4p)) {
                System.out.println("M4 = "+M4.toString(16));
                System.out.println("M4' = "+M4p.toString(16));
                System.out.println("Verification status : "+"M4 = M4'");    
            } else {
                System.out.println("M4 = "+M4.toString(16));
                System.out.println("M4' = "+M4p.toString(16));
                System.out.println("Verification status: "+"M4 != M4'");
                return;    
            }

            //CS retrieves aj' from PIDj' in Ls
            BigInteger alphajp = getAlpha(PIDjp, Ls);
            //If the a'j = 0 then PID'j is not valid 
            if (alphajp.toString()=="0") {
                System.out.println("The identity PID'j is not found in Ls");
                return;
            }

            //CS computes M5,M6,M7
            BigInteger M5,M6,M7;
            M5 = Hash(PIDjp.toString()+alphajp.toString()).xor(r1p);
            M6 = Hash(PIDjp.toString()+PIDs.toString()+alphajp.toString()+r1p.toString()).xor(PIDip);
            M7 = Hash(PIDip.toString()+PIDjp.toString()+PIDs.toString()+alphajp.toString()+r1p.toString());
        
        //---4.4.(4)
            //Drone Vj computes r1'', PIDi'', and M7'
            BigInteger r1pp, PIDipp, M7p;
            r1pp = M5.xor(Hash(PIDj.toString()+alphaj.toString()));
            PIDipp = M6.xor(Hash(PIDj.toString()+PIDs.toString()+alphaj.toString()+r1pp.toString()));
            M7p = Hash(PIDipp.toString()+PIDj.toString()+PIDs.toString()+alphaj.toString()+r1pp.toString());

        //---4.4.(5)
            //Drone Vj check M7'=M7
            System.out.println("\nDrone Vj checks for M7");
            if (M7.equals(M7p)) {
                System.out.println("M7 = "+M7.toString(16));
                System.out.println("M7' = "+M7p.toString(16));
                System.out.println("Verification status : "+"M7 = M7'");    
            } else {
                System.out.println("M7 = "+M7.toString(16));
                System.out.println("M7' = "+M7p.toString(16));
                System.out.println("Verification status: "+"M7 != M7'");
                return;    
            }
            
            //Drone Vj chooses 160 bits r2 
            BigInteger r2 = new BigInteger(160, rnd);
            
            //Drone Vj computes M8, M9, M10, SKji
            BigInteger M8,M9,M10,SKji;
            M8 = Hash(PIDj.toString()+PIDipp.toString()+r1pp.toString()).xor(r2);
            M9 = Hash(r1pp.toString()+r2.toString());
            M10 = Hash(PIDipp.toString()+PIDj.toString()+PIDs.toString()+r1pp.toString()+r2.toString()+M9.toString());
            SKji = Hash(PIDipp.toString()+PIDj.toString()+PIDs.toString()+M9.toString());
            
            System.out.println("Session Key SKji = "+SKji.toString(16));

        //---4.4.(6)
            BigInteger r2p, M9p, M10p, SKij;
            //User Ui computes r2', M9',M10'
            r2p = M8.xor(Hash(PIDj.toString()+PIDi.toString()+r1.toString()));
            M9p = Hash(r1.toString()+r2p.toString());
            M10p = Hash(PIDi.toString()+PIDj.toString()+PIDs.toString()+r1.toString()+r2p.toString()+M9p.toString());

            //User Ui checks M10' = M10
            System.out.println("\nUser Ui checks for M10");
            if (M10.equals(M10p)) {
                System.out.println("M10 = "+M10.toString(16));
                System.out.println("M10' = "+M10p.toString(16));
                System.out.println("Verification status : "+"M10 = M10'");    
            } else {
                System.out.println("Verification status: "+"M10 != M10'");
                return;    
            }

            //User Ui calculates the common session key SKij 
            SKij = Hash(PIDi.toString()+PIDj.toString()+PIDs.toString()+M9p.toString());
            System.out.println("Session Key SKij = "+SKij.toString(16));

            
        System.out.println("\n\n---- Conclusion ----");
        if (SKij.equals(SKji)) {
            System.out.println("User Ui and Drone Vj using same session key (SKij = SKji)");
            System.out.println(SKij.toString(16));
        } else {
            System.out.println("User and Drone have different session key (SKij != SKji)");
        }
    //end of main 
    }

    private static BigInteger Hash(String hash) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		//This method to compute Hash from string as an input                
		//could change to SHA1,SHA-128, SHA-256, SHA-512
		MessageDigest md = MessageDigest.getInstance("SHA-256"); 
		md.update(hash.toString().getBytes("UTF-8")); 
		byte[] digest = md.digest();

		StringBuffer sb = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
         sb.append(Integer.toString((digest[i] & 0xff) + 0x100, 16).substring(1));
        }

        return new BigInteger(sb.toString(),16);
    }
    
    private static BigInteger getAlpha(BigInteger PID, String[][] LS) {
        //This method to get alpha from its PID in Ls
        String alpha="0";
        for (int i=0;i<LS.length;i++) {
            if (PID.toString().equals(LS[i][2])) {
                alpha=LS[i][1];
            }    
        }
        return new BigInteger(alpha);
    }
    
}
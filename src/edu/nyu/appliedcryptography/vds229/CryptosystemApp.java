package edu.nyu.appliedcryptography.vds229;

import java.util.*;

/***
 * This is app uses a [modified] RSA public/private cryptosystem to
 * create digital certificates and perform authentication according to the
 * specifications given by the NYU 3205 Applied Cryptography final project. 
 * @author Vangie
 */
public class CryptosystemApp {
  /**
   * Immediately escapes the static context and runs the program.
   */
  public static void main(String[] args) {
    CryptoUser alice = new CryptoUser();
    alice.run();
    
    CryptoUser trent = new CryptoUser();
    trent.dontprint = true;
    trent.run();
    
    CryptosystemApp app = new CryptosystemApp();
    app.run(alice, trent);
  }
  
  
  
  /*
   * CRYPTOSYSTEM VARIABLES
   */
  //For printing testing purposes
  boolean verboseoverride = false, dontprint = false, debug = false;
  //A random-number generator
  private Random randomizer = new Random();
  //For section 5
  //r is certificate
  public String r;
  //hr is hash(r), s is signature
  public int hr, s;
  //For section 6
  //random large u and k the number of leading 0 bits in u
  public int k, u;
  //hu is hash h(u), v is decrypted hu with alice.d, ev is encrypted v with alice.e
  public int hu, v, ev;
  
  public void run(CryptoUser alice, CryptoUser trent) {
    /*
     * PART 5
     */
    System.out.println("185 =======================================");
    this.generateDigitalCertificate(alice, trent);
    this.print(true, "r = "+this.r+" (binary)");
    this.print(true, "h(r) = "+this.getBitRepresentation(this.hr,8)+"");
    this.print(true, "s = "+this.getBitRepresentation(this.s,32)+"");
    System.out.println("187 =======================================");
    this.print(true, "h(r) = "+this.hr);
    this.print(true, "s = "+this.s);
    
    /*
     * PART 6
     */
    System.out.println("206 =======================================");
    this.determineKU(alice);
    this.print(true, "k = "+this.k);
    this.print(true, "u = "+this.u);
    System.out.println("208 =======================================");
    this.print(true,"u = "+this.getBitRepresentation(u,32));
    System.out.println("215 =======================================");
    this.getAliceDecryption(alice);
    this.print(true, "h(u) = "+this.hu+" ("+this.getBitRepresentation(this.hu,8)+")");
    this.print(true, "v = "+this.v+" ("+this.getBitRepresentation(this.v,32)+")");
    this.print(true, "E(e,v) = "+this.ev+" ("+this.getBitRepresentation(this.ev,8)+")");
    System.out.println("219 =======================================");
    this.getBobEncryptionTrace(alice);
  }
  
  private void print(boolean verbose, String message) {
    //verboseoverride set to true if you always want to print traces
    if(verboseoverride) {
      System.out.println(message);
    } else if(!dontprint && verbose) {
      //dontprint allows you to override verbose and not print any traces 
      System.out.println(message);
    }
  }
  private void debug(String message) {
    //Prints the passed message only in debug mode
    if(debug) {
      System.out.println(message);
    }
  }
  private String getBitRepresentation(int x, int bits) {
    this.debug("getBitRepresentation("+x+","+bits+")");
    StringBuilder str = new StringBuilder();
    String bin = Integer.toBinaryString(x);
    for(int b=bin.length(); b<bits; b++) {
      str.append("0");
    }
    str.append(bin);
    return str.toString();
  }

  private void generateDigitalCertificate(CryptoUser alice, CryptoUser trent) {
    boolean trace = false;
    //r
    this.r = this.getR("Alice",alice.n,alice.e);
    //h(r)
    this.hr = this.getOnewayHash(r, trace);
    //s
    this.s = this.getFastExponentiation(hr, trent.d, trent.n, trace);
  }
  private String getR(String name, int n, int e) {
    //First part: name
    StringBuilder rtemp = new StringBuilder("");
    char[] namearr = name.toCharArray();
    for(int i=0; i<6; i++) {
      if(i<namearr.length) {
        String letter = Integer.toBinaryString((int)namearr[i]);
        //pad 0s if bit representation of char is not 8 bits
        for(int ex=letter.length(); ex<8; ex++) {
          rtemp.append("0");
        }
        rtemp.append(letter);
      } else {
        //pad 0s for the blanks (if name shorter than 6 chars) at the front
        rtemp.insert(0,"00000000");
      }
    }
    //Second part: n
    rtemp.append(this.getBitRepresentation(n,32));
    //Third part: e
    rtemp.append(this.getBitRepresentation(e,32));
    return rtemp.toString();
  }
  private int getOnewayHash(String x, boolean verbose) {
    this.debug(""+x.length());
    char[] xarr = x.toCharArray();
    char[] curr = x.substring(0,8).toCharArray();
    for(int i=8; i<xarr.length; i++) {
      //this.debug(i%8+": "+xarr[i]+" "+curr[i%8]+" "+new String(curr));
      if(xarr[i] == curr[i%8]) {
        curr[i%8] = '0';
      } else {
        curr[i%8] = '1';
      }
    }
    this.debug(new String(curr));
    int ans = Integer.parseInt(new String(curr),2);
    this.debug(""+ans);
    return ans;
  }
  private int getFastExponentiation(int c, int d, int n, boolean verbose) {
    this.print(verbose,"Fast exponentiation to solve: y = c^d mod(n) = "+c+"^"+d+" mod("+n+")");
    //Use fast exponentiation algorithm given on p110 in notes, figure 64
    String dbin = Integer.toBinaryString(d);
    this.print(verbose, "d to binary: "+d+" -> "+dbin);
    int y = c;
    this.print(verbose, "Bit 1. Initial y = "+y);
    for(int i=1; i<dbin.length(); i++) {
      this.print(verbose, "Bit "+(i+1)+". y = "+y+"^2 mod("+n+")");
      y = (int)Math.pow(y, 2)%n;
      this.print(verbose, "Bit "+(i+1)+". y = "+y);
      if(dbin.charAt(i) == '1') {
        this.print(verbose, "Bit "+(i+1)+". y = ("+y+"*"+c+") mod("+n+")");
        y = (c*y)%n;
        this.print(verbose, "Bit "+(i+1)+". y = "+y);
      }
    }
    this.print(verbose, "Final y = "+y);
    return y;
  }

  private void determineKU(CryptoUser alice) {
    boolean verbose = false;
    //get k
    char[] bitn = this.getBitRepresentation(alice.n,32).toCharArray();
    for(int c=0; c<bitn.length; c++) {
      if(bitn[c] == '1') {
        this.k = c+1;
        break;
      }
    }
    this.print(verbose,"k = "+this.k);
    //get u
    StringBuilder str = new StringBuilder("");
    for(int c=0; c<k; c++) {
      str.append("0");
    }
    str.append("1");
    for(int c=str.length(); c<32; c++) {
      str.append(""+Math.abs(randomizer.nextInt())%2);
    }
    print(verbose,"u = "+str.toString()+" (binary)");
    this.u = Integer.parseInt(str.toString(),2);
    print(verbose,"u = "+this.u);
  }
  private void getAliceDecryption(CryptoUser alice) {
    boolean verbose = false;
    boolean trace = false;
    this.print(verbose, "u = "+this.u+" ("+this.getBitRepresentation(this.u,32)+")");
    this.hu = this.getOnewayHash(this.getBitRepresentation(this.u,32),trace);
    this.print(verbose, "h(u) = "+this.hu+" ("+this.getBitRepresentation(this.hu,8)+")");
    this.v = this.getFastExponentiation(this.hu, alice.d, alice.n, trace);
    this.print(verbose, "v = "+this.v+" ("+this.getBitRepresentation(this.v,32)+")");
    this.ev = this.getFastExponentiation(this.v, alice.e, alice.n, trace);
    this.print(verbose, "E(e,v) = "+this.ev+" ("+this.getBitRepresentation(this.ev,8)+")");
  }
  private void getBobEncryptionTrace(CryptoUser alice) {
    boolean verbose = true;
    this.print(verbose, "Trace for encryption of "+this.v+" (E("+alice.e+","+this.v+"))");
    this.getFastExponentiation(this.v, alice.e, alice.n, verbose);
  }

}

class CryptoUser {
  //For printing testing purposes
  boolean verboseoverride = false, dontprint = false, debug = false;
  //A random-number generator
  private Random randomizer = new Random();
  //A list of past generated 7-bit random numbers tried so we don't test duplicates
  private List<Integer> pastrandoms = new ArrayList<Integer>();
  //The past quotients generated while checking the GCD(e,n), used to determine d
  LinkedList<Integer> quotient = new LinkedList<Integer>();
  //The important cryptosystem values
  //e: public key, d: private key
  int p, q, n, e, d;
  
  /**
   * This is the main program, running through Part 4 of Assignment
   */
  public void run() {
    /*
     * PART 4
     */
    this.print(true,"104 =======================================");
    this.generateInitialpq();
    
    this.print(true,"119 =======================================");
    this.getNonPrimeTrace();

    this.print(true,"123 =======================================");
    this.getPrimePQ();
    
    this.n = this.p*this.q;
    this.debug("-> final n = "+this.n);
    
    this.print(true,"142 =======================================");
    this.getPublicKey();
    
    this.print(true,"152 =======================================");
    this.getPrivateKey();
    
    this.print(true,"156 =======================================");
    this.showAllValues();
  }
  
  private void print(boolean verbose, String message) {
    //verboseoverride set to true if you always want to print traces
    if(this.verboseoverride) {
      System.out.println(message);
    } else if(!this.dontprint && verbose) {
      //dontprint allows you to override verbose and not print any traces 
      System.out.println(message);
    }
  }
  private void debug(String message) {
    //Prints the passed message only in debug mode
    if(this.debug) {
      System.out.println(message);
    }
  }

  private void generateInitialpq() {
    //Generate 2 random numbers, p & q
    this.p = generateRandomNumber(7,true);
    do {
      //Generate q that does not equal p
      this.q = generateRandomNumber(7,false);
    } while(this.p == this.q);
    pastrandoms.add(this.p);
    pastrandoms.add(this.q);
    debug("-> Initial p = "+this.p);
    debug("-> Initial q = "+this.q);
  }
  private int generateRandomNumber(int bits, boolean verbose) {
    //bits is how many bits the random number should be
    //Its binary notation will start with 1 and end with 1
    int x = 1;
    print(verbose,"Generating a random "+bits+"-bit integer:");
    print(verbose,"Bit 1. x = 1 (least significant bit is always 1, 1*2^0=1)");
    for(int i=1; i<(bits-1); i++) {
      int temp = Math.abs(randomizer.nextInt());
      print(verbose,"Random number "+i+" generated: "+temp);
      print(verbose,"Bit "+(i+1)+". Least significant bit of "+temp+" is "+temp%2);
      print(verbose,"x = "+x+" + "+temp%2+"*2^"+i+" = "+x+" + "+(int)Math.pow(2, i)*(temp%2));
      x = x + (int)Math.pow(2, i)*(temp%2);
      print(verbose,"x = "+x);
    }
    print(verbose,"Bit "+bits+". Most significant bit of random number is always 1.");
    print(verbose,"x = "+x+" + "+(int)Math.pow(2, bits-1));
    x = x + (int)Math.pow(2, bits-1);
    print(verbose,"x = "+x);
    print(verbose,"Random "+bits+"-number x = "+x);
    return x;
  }
  
  private void getNonPrimeTrace() {
    boolean verbose = true;
    print(verbose,"Generating primality check trace of non-prime number:");
    if(!this.isPrime(this.p, false)) {
      this.print(verbose,"Initial p is not prime.");
      isPrime(this.p, true);
    } else if(!this.isPrime(this.q, false)) {
      this.print(verbose,"Initial q is not prime.");
      this.isPrime(this.q, true);
    } else {
      this.print(verbose,"Both initial p and q are prime.");
      this.print(verbose,"Generating a non-prime number to show non-prime trace:");
      int notprime;
      do {
        notprime = generateRandomNumber(7,false);
      } while(this.isPrime(notprime, false));
      this.isPrime(notprime, true);
      this.pastrandoms.add(notprime);
    }
  }
  private void getPrimePQ() {
    //Test if p & q are prime
    //If not, continue generating random numbers until both are prime
    while(!this.isPrime(this.p, false)) {
      do {
        this.p = this.generateRandomNumber(7,false);
      } while (this.pastrandoms.contains(this.p));
      this.pastrandoms.add(this.p);
      this.debug("-> p = generateRandomNumber("+this.p+")");
    }
    while(!this.isPrime(this.q, false)) {
      do {
        this.q = this.generateRandomNumber(7,false);
      } while (this.pastrandoms.contains(this.q));
      pastrandoms.add(this.q);
      this.debug("-> q = generateRandomNumber("+this.q+")");
    }
    this.print(true,"Generating primality check trace of [probably] prime: "+this.p);
    this.isPrime(this.p,true);
    this.print(true,"-> final p = "+this.p);
    this.print(true,"-> final q = "+this.q);
  }
  private boolean isPrime(int x, boolean verbose) {
    //Tests if the given int is a prime number by modified Miller-Rabin
    print(verbose,"Testing if "+x+" is prime:");
    //List of tested values so that you don't calculate redundant values
    List<Integer> pastAvalues = new ArrayList<Integer>();
    int a = 0;
    for(int i=0; i<20; i++) {
      //generate a random number 0 < a < n
      do {
        a = Math.abs(randomizer.nextInt())%x;
      } while(a == 0 || pastAvalues.contains(a));
      pastAvalues.add(a);
      debug("Test "+(i+1)+". a = "+a);
      
      if(!this.passesMillerRabinFastExp(a, x, false)) {
        this.print(verbose,"Test "+(i+1)+". (a = "+a+") fails primality test for n = "+x);
        this.passesMillerRabinFastExp(a, x, verbose);
        return false;
      } else {
        this.print(verbose,"Test "+(i+1)+". (a = "+a+") passes primality test for n = "+x);
      }
    }
    this.print(verbose,"Trace of (a = "+a+") which passed primality test:");
    this.passesMillerRabinFastExp(a, x, verbose);
    this.print(verbose,"20 tests passed primality test for n = "+x);
    this.print(verbose,x+" is probably prime");
    return true;
  }
  private boolean passesMillerRabinFastExp(int a, int n2, boolean verbose) {
    //Fast Exponentiation method for obtaining a^(n-1) mod(n)
    this.print(verbose,"Performing fast exponentiation: y = "+a+"^("+n2+"-1) mod("+n2+")");
    //binary rep of n-1
    String bin = Integer.toBinaryString(n2-1);
    this.print(verbose,"Binary representation of (n-1) is "+bin);
    int y = a;
    this.print(verbose, "1. Initial y = a = "+y);
    int square;
    for(int i=1; i<bin.length(); i++) {
      square = (int)Math.pow(y, 2)%n2;
      this.print(verbose, (i+1)+". y = "+y+"^2 mod("+n2+") = "+square);
      if(y!=1 && y!=(n2-1) && square==1) {
        this.print(verbose, (i+1)+". FAILED: y = "+y+" (!= 1 or n-1) and y^2 mod(n) = "+square);
        return false;
      }
      y = square;
      if(bin.charAt(i) == '1') {
        square = (a*y)%n2;
        this.print(verbose, (i+1)+". bit was 1: y = "+y+"*"+a+" mod("+n2+") = "+square);
        y = square;
      }
    }
    if(y != 1) {
      this.print(verbose, "FAILED: Final y = a^(n-1)mod(n) = "+y+" != 1");
      return false;
    } else {
      this.print(verbose, "PASSED: Final y = a^(n-1)mod(n) = "+y+" != 1");
      return true;
    }
  }
  
  private void getPublicKey() {
    boolean verbose = true;
    this.e = 3; //always start with 3
    int n2 = (this.p-1)*(this.q-1);
    this.print(verbose, "(p - 1)*(q - 1) = "+n2);
    while(this.e<n2 && !this.isRelativelyPrime(this.e,n2,verbose)) {
      this.e++;
      if(this.e==n2) {
        //No relatively prime value e found; Regenerate prime values p, q
        this.print(verbose,"No relatively prime e found. Regenerating primes p & q.");
        this.p = this.generateRandomNumber(7,false);
        this.q = this.generateRandomNumber(7,false);
        this.getPrimePQ();
        this.print(verbose,"-> New p = "+this.p);
        this.print(verbose,"-> New q = "+this.q);
        this.n = this.p*this.q;
        n2 = (this.p-1)*(this.q-1);
        this.debug("-> New n = "+this.n);
        this.print(verbose, "(p - 1)*(q - 1) = "+n2);
        this.e = 3;
      }
    }
    this.print(verbose,"Final e = "+e+" is co-prime with phi(n) = (p-1)*(q-1)");
  }
  private boolean isRelativelyPrime(int test, int n2, boolean verbose) {
    this.print(verbose,"Trying e = "+test);
    //Use Extended Euclidean Algorithm to determine if e is relatively prime
    int big = n2;
    int small = test;
    this.quotient = new LinkedList<Integer>(); //keep track of quotients to calculate d later
    
    while(big%small > 0) {
      this.quotient.add((int)(big/small));
      int r = big%small;
      this.print(verbose,big+" = "+(int)(big/small)+"*"+small+" + "+r);
      big = small;
      small = r;
    }
    if(small == 1) {
      //if gcd = 1, then they are relatively prime
      this.print(verbose, "Last remainder = 1");
      this.print(verbose,test+" and "+n2+" are relatively prime.");
      return true;
    } else {
      this.print(verbose, "Last remainder = 0");
      this.print(verbose,test+" and "+n2+" are not relatively prime.");
      return false;
    }
  }
  private void getPrivateKey() {
    //Get multiplicative inverse of e
    boolean verbose = true;
    this.print(verbose, "Generating multiplicative inverse of "+this.e);
    int p0 = 0, p1 = 1;
    int n2 = (this.p-1)*(this.q-1);
    while(quotient.size()>0) {
      int temp = p1;
      int quot = this.quotient.remove(0);
      p1 = (p0 - p1*quot)%n2;
      print(verbose,"t = "+p0+" - "+temp+"*"+quot+" mod("+n2+") = "+p1);
      p0 = temp;
      if(p1<0) {
        print(verbose,"t = "+p1+" mod("+n2+") = "+(n2+p1));
        p1 = n2 + p1;
      }
    }
    this.print(verbose,"private key d = t = "+p1);
    this.d = p1;
  }

  private void showAllValues() {
    boolean verbose = true;
    this.print(verbose,"p = "+this.p+" ("+this.getBitRepresentation(this.p, 32)+")");
    this.print(verbose,"q = "+this.q+" ("+this.getBitRepresentation(this.q, 32)+")");
    this.print(verbose,"n = "+this.n+" ("+this.getBitRepresentation(this.n, 32)+")");
    this.print(verbose,"e = "+this.e+" ("+this.getBitRepresentation(this.e, 32)+")");
    this.print(verbose,"d = "+this.d+" ("+this.getBitRepresentation(this.d, 32)+")");
  }
  private String getBitRepresentation(int x, int bits) {
    this.debug("getBitRepresentation("+x+","+bits+")");
    StringBuilder str = new StringBuilder();
    String bin = Integer.toBinaryString(x);
    for(int b=bin.length(); b<bits; b++) {
      str.append("0");
    }
    str.append(bin);
    return str.toString();
  }
  
}



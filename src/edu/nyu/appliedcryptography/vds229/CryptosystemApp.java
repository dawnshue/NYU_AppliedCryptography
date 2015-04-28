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
    CryptosystemApp alice = new CryptosystemApp();
    alice.dontprint = false;
    alice.debug = false;
    alice.run();
    
    CryptosystemApp trent = new CryptosystemApp();
    trent.dontprint = true;
    trent.debug = false;
    trent.verboseoverride = false;
    trent.run();
    
    alice.run2(alice, trent);
  }
  
  /*
   * VARIABLES
   */
  //For printing testing purposes
  boolean verboseoverride = false, dontprint = false, debug = true;
  //A random-number generator
  private Random randomizer = new Random();
  //A list of past generated 7-bit random numbers so we don't test duplicates
  private List<Integer> pastvalues = new ArrayList<Integer>();
  //The past quotients generated while checking the GCD(e,n), used to determine d
  LinkedList<Integer> quotient = new LinkedList<Integer>();
  //The important cryptosystem values
  //e: public key, d: private key
  public int p, q, n, e, d;
  //For section 5, hr is hash(r), s is signature
  public String r;
  public int hr, s;
  //For section 6
  public int k, u;
  public int hu, v, ev;
  
  /**
   * This is the main program, running through all the steps in the 
   * project specification.
   */
  private void test() {
    this.passesMillerRabinFastExp(8, 10, true);
  }
  public void run() {
    /*
     * PART 4
     */
    this.print(true,"104 =======================================");
    this.generateInitialpq();
    
    this.print(true,"119 =======================================");
    this.getNonPrimeTrace();
    //!!!!!!!!!!!!!!!!!!!
    //ALGORITHM FOR ISPRIME NEEDS TO BE MODIFIED
    //!!!!!!!!!!!!!!!!!!!
    this.print(true,"123 =======================================");
    this.getPrimePQ();
    
    n = p*q;
    this.debug("-> final n = "+n);
    
    this.print(true,"142 =======================================");
    this.getPublicKey();
    
    this.print(true,"152 =======================================");
    this.getPrivateKey();
    
    this.print(true,"156 =======================================");
    this.showAllValues();
  }
  public void run2(CryptosystemApp alice, CryptosystemApp trent) {
    /*
     * PART 5
     */
    System.out.println("185 =======================================");
    this.getDigitalCertificate(alice, trent);
    this.print(true, "h(r) = "+this.getByteRepresentation(hr)+"");
    this.print(true, "s = "+this.get32BitRepresentation(s)+"");
    System.out.println("187 =======================================");
    this.print(true, "h(r) = "+hr);
    this.print(true, "s = "+s);
    
    /*
     * PART 6
     */
    System.out.println("206 =======================================");
    this.determineKU();
    System.out.println("208 =======================================");
    this.print(true,"u = "+this.get32BitRepresentation(u));
    System.out.println("215 =======================================");
    this.getAliceDecryption(alice);
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

  private void generateInitialpq() {
    //Generate 2 random numbers, p & q
    p = generateRandomNumber(true);
    do {
      //Generate q that does not equal p
      q = generateRandomNumber(false);
    } while(p == q);
    pastvalues.add(p);
    pastvalues.add(q);
    debug("-> Initial p = "+p);
    debug("-> Initial q = "+q);
  }
  private int generateRandomNumber(boolean verbose) {
    int p = 1;
    print(verbose,"Generating a random 7-bit integer:");
    print(verbose,"x = 1 (because last bit is 1, 1*2^0=1)");
    for(int i=1; i<6; i++) {
      int temp = Math.abs(randomizer.nextInt());
      print(verbose,"Random number "+i+" generated: "+temp);
      print(verbose,"Least significant bit of "+temp+" is "+temp%2);
      print(verbose,"x = "+p+" + "+(int)Math.pow(2, i)*(temp%2));
      p = p + (int)Math.pow(2, i)*(temp%2);
      print(verbose,"x = "+p);
    }
    print(verbose,"Most significant bit of random number is always 1.");
    print(verbose,"x = "+p+" + "+(int)Math.pow(2, 6));
    print(verbose,"x = "+(p+(int)Math.pow(2, 6)));
    p = p + (int)Math.pow(2, 6);
    return p;
  }
  
  private void getNonPrimeTrace() {
    if(!isPrime(p, false)) {
      isPrime(p, true);
    } else if(!isPrime(q, false)) {
      isPrime(q, true);
    } else {
      print(true,"Both p and q are prime.");
      print(true,"Generating a non-prime number to show non-prime trace:");
      int notprime;
      do {
        notprime = generateRandomNumber(false);
      } while(isPrime(notprime, false));
      isPrime(notprime, true);
      pastvalues.add(notprime);
    }
  }
  private void getPrimePQ() {
    //Test if p & q are prime
    //If not, continue generating random numbers until both are prime
    while(!this.isPrime(p, false)) {
      do {
        p = this.generateRandomNumber(false);
      } while (pastvalues.contains(p));
      pastvalues.add(p);
      this.debug("-> p = generateRandomNumber("+p+")");
    }
    while(!this.isPrime(q, false)) {
      do {
        q = this.generateRandomNumber(false);
      } while (pastvalues.contains(q));
      pastvalues.add(q);
      this.debug("-> q = generateRandomNumber("+q+")");
    }
    this.isPrime(p,true);
    this.print(true,"-> final p = "+p);
    this.print(true,"-> final q = "+q);
  }
  private boolean isPrime(int n, boolean verbose) {
    //Tests if the given int is a prime number by modified Miller-Rabin
    print(verbose,"Testing if "+n+" is prime:");
    //List of tested values so that you don't calculate redundant values
    List<Integer> pastAvalues = new ArrayList<Integer>();
    int a = 0;
    for(int i=0; i<20; i++) {
      //generate a random number 0 < a < n
      do {
        a = Math.abs(randomizer.nextInt())%n;
      } while(a == 0 || pastAvalues.contains(a));
      pastAvalues.add(a);
      this.debug("Test "+(i+1)+" with a = "+a);
      
      if(!this.passesMillerRabinFastExp(a, n, false)) {
        this.print(verbose,"Test "+(i+1)+" (a = "+a+") fails primality test for n = "+n);
        this.passesMillerRabinFastExp(a, n, true);
        return false;
      } else {
        this.debug("Test "+(i+1)+" (a = "+a+") passes primality test for n.");
      }
    }
    this.print(verbose,"Last test (a = "+a+") passes primality test for n.");
    this.passesMillerRabinFastExp(a, n, true);
    this.print(verbose,n+" is probably prime");
    return true;
  }
  private boolean passesMillerRabinFastExp(int a, int n2, boolean verbose) {
    //Fast Exponentiation method for obtaining a^(n-1) mod(n)
    this.print(verbose,"Fast exponentiation for "+a+"^("+n2+"-1) mod("+n2+")");
    //binary rep of n-1
    String bin = Integer.toBinaryString(n2-1);
    this.print(verbose,"Binary of (n-1) is "+bin);
    int y = a;
    this.print(verbose, "y = "+y);
    int square;
    for(int i=1; i<bin.length(); i++) {
      square = (int)Math.pow(y, 2)%n2;
      this.print(verbose, "y = "+y+"^2 mod("+n2+") = "+square);
      if(y!=1 && y!=(n2-1) && square==1) {
        this.print(verbose, "FAIL: y = "+y+" (!= 1 or n-1) and y^2 mod(n) = "+square);
        return false;
      }
      y = square;
      if(bin.charAt(i) == '1') {
        square = (a*y)%n2;
        this.print(verbose, "y = "+y+"*"+a+" mod("+n2+") = "+square);
        y = square;
      }
    }
    if(y != 1) {
      this.print(verbose, "Final y = a^(n-1)mod(n) = "+y+" != 1, so n cannot be prime.");
      return false;
    } else {
      this.print(verbose, "Final y = a^(n-1)mod(n) = "+y+" != 1, so n probably prime.");
      return true;
    }
  }
  
  private void getPublicKey() {
    boolean verbose = true;
    ArrayList<Integer> pastEvalues = new ArrayList<Integer>();
    e = 3;
    int n2 = (p-1)*(q-1);
    while(e<n2 && !isRelativelyPrime(e,n2,true)) {
      e++;
      if(e==n2) {
        //No relatively prime value e found
        //Regenerate prime values p, q
        this.print(verbose,"-> No relatively prime e found. Regenerating primes p & q.");
        p = this.generateRandomNumber(false);
        q = this.generateRandomNumber(false);
        this.getPrimePQ();
        this.print(verbose,"-> New p = "+p);
        this.print(verbose,"-> New q = "+q);
        n = p*q;
        n2 = (p-1)*(q-1);
        this.print(verbose,"-> New n = "+n);
        e = 3;
      }
    }
    print(true,"-> final e = "+e);
  }
  private boolean isRelativelyPrime(int e, int n2, boolean verbose) {
    print(true,"Trying e = "+e);
    //Use Extended Euclidean Algorithm to determine if e is relatively prime
    int big = n2;
    int small = e;
    quotient = new LinkedList<Integer>();
    
    while(big%small > 0) {
      quotient.add((int)(big/small));
      int r = big%small;
      this.print(verbose,big+" = "+(int)(big/small)+"*"+small+" + "+r);
      big = small;
      small = r;
    }
    if(small == 1) {
      //if gcd = 1, then they are relatively prime
      this.print(verbose,e+" and "+n2+" are relatively prime.");
      return true;
    } else {
      this.print(verbose,e+" and "+n2+" are not relatively prime.");
      return false;
    }
  }
  private void getPrivateKey() {
    //Get multiplicative inverse of e
    boolean verbose = true;
    int p0 = 0, p1 = 1;
    int n2 = (p-1)*(q-1);
    while(quotient.size()>0) {
      int temp = p1;
      int quot = quotient.remove(0);
      p1 = (p0 - p1*quot)%n2;
      print(verbose,"t = "+p0+" - "+temp+"*"+quot+" mod("+n2+") = "+p1);
      p0 = temp;
      if(p1<0) {
        print(verbose,"t = "+p1+" mod("+n2+") = "+(n2+p1));
        p1 = n2 + p1;
      }
    }
    d = p1;
    print(true,"-> final d = "+d);
  }

  private void showAllValues() {
    this.print(true,"p = "+p+" ("+get32BitRepresentation(p)+")");
    this.print(true,"q = "+q+" ("+get32BitRepresentation(q)+")");
    this.print(true,"n = "+n+" ("+get32BitRepresentation(n)+")");
    this.print(true,"e = "+e+" ("+get32BitRepresentation(e)+")");
    this.print(true,"d = "+d+" ("+get32BitRepresentation(d)+")");
  }
  private String get32BitRepresentation(int x) {
    this.debug("get32BitRepresentation("+x+")");
    StringBuilder str = new StringBuilder();
    String bin = Integer.toBinaryString(x);
    for(int b=bin.length(); b<32; b++) {
      str.append("0");
    }
    str.append(bin);
    return str.toString();
  }
  private String getByteRepresentation(int x) {
    this.debug("getByteRepresentation("+x+")");
    StringBuilder str = new StringBuilder();
    String bin = Integer.toBinaryString(x);
    for(int b=bin.length(); b<8; b++) {
      str.append("0");
    }
    this.debug("Padded: "+str.toString());
    str.append(bin);
    this.debug("binary: "+bin);
    return str.toString();
  }

  private void getDigitalCertificate(CryptosystemApp alice, CryptosystemApp trent) {
    boolean verbose = true;
    boolean trace = false;
    //r
    r = this.getR("Alice",alice.n,alice.e);
    this.print(verbose, "r = "+r);
    //hr
    hr = this.getOnewayHash(r, trace);
    //s
    s = this.getFastExponentiation(hr, trent.d, trent.n, trace);
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
    rtemp.append(this.get32BitRepresentation(n));
    //Third part: e
    rtemp.append(this.get32BitRepresentation(e));
    return rtemp.toString();
  }
  private int getOnewayHash(String x, boolean verbose) {
    this.debug(""+x.length());
    char[] xarr = x.toCharArray();
    char[] curr = x.substring(0,8).toCharArray();
    int curriter = 0;
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
    this.debug("c^d mod(n) = "+c+"^"+d+" mod("+n+")");
    //decrypt message m from cipher c: m = c^(d) mod(n)
    //Use fast exponentiation algorithm given on p110 in notes, figure 64
    String dbin = Integer.toBinaryString(d);
    this.print(verbose, "d to binary: "+d+" -> "+dbin);
    this.print(verbose, "y = "+c);
    int y = c;
    for(int i=1; i<dbin.length(); i++) {
      this.print(verbose, "y = "+y+"^2 mod("+n+")");
      y = (int)Math.pow(y, 2)%n;
      if(dbin.charAt(i) == '1') {
        this.print(verbose, "y = "+y+"*"+c+" mod("+n+")");
        y = (c*y)%n;
      }
    }
    this.print(verbose, "y = "+y);
    return y;
  }
  private void determineKU() {
    //get k
    char[] bitn = this.get32BitRepresentation(n).toCharArray();
    for(int c=bitn.length-1; c>=0; c--) {
      if(bitn[c] == '1') {
        k = c+1;
      }
    }
    print(true,"k = "+k);
    //get u
    StringBuilder str = new StringBuilder("");
    for(int c=0; c<k; c++) {
      str.append("0");
    }
    str.append("1");
    for(int c=0; c<(32-k-2); c++) {
      str.append(""+Math.abs(randomizer.nextInt())%2);
    }
    str.append("1");
    u = Integer.parseInt(str.toString(),2);
    print(true,"u = "+u);
  }
  private void getAliceDecryption(CryptosystemApp alice) {
    boolean verbose = true;
    boolean trace = false;
    this.print(verbose, "u = "+u+" ("+this.get32BitRepresentation(u)+")");
    hu = this.getOnewayHash(this.get32BitRepresentation(u),trace);
    this.print(verbose, "h(u) = "+hu+" ("+this.getByteRepresentation(hu)+")");
    v = this.getFastExponentiation(hu, alice.d, alice.n, trace);
    this.print(verbose, "v = "+v+" ("+this.get32BitRepresentation(v)+")");
    ev = this.getFastExponentiation(v, alice.e, alice.n, trace);
    this.print(verbose, "E(e,v) = "+ev+" ("+this.getByteRepresentation(ev)+")");
  }
  private void getBobEncryptionTrace(CryptosystemApp alice) {
    boolean verbose = true;
    this.print(verbose, "Trace for encryption of "+v+" (E(e,v))");
    this.getFastExponentiation(v, alice.e, alice.n, true);
  }

}

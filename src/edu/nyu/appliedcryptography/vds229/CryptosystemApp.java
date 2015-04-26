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
    //new CryptosystemApp().test();
    new CryptosystemApp().run(); //get out of static context ASAP
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
  //e: public key
  public int p, q, n, e, d;
  
  /**
   * This is the main program, running through all the steps in the 
   * project specification.
   */
  private void test() {
    this.isPrime(11,true);
  }
  private void run() {
    /*
     * PART 4
     */
    System.out.println("104 =======================================");
    this.generateInitialpq();
    
    System.out.println("119 =======================================");
    this.getNonPrimeTrace();
    //!!!!!!!!!!!!!!!!!!!
    //ALGORITHM FOR ISPRIME NEEDS TO BE MODIFIED
    //!!!!!!!!!!!!!!!!!!!
    System.out.println("123 =======================================");
    this.getPrimePQ();
    
    n = p*q;
    this.debug("### final n = "+n);
    
    System.out.println("142 =======================================");
    this.getPublicKey();
    
    System.out.println("152 =======================================");
    this.getPrivateKey();
    
    System.out.println("156 =======================================");
    this.showAllValues();
    
    /*
     * PART 5
     */
    System.out.println("185 =======================================");
    this.getDigitalCertificate();
    System.out.println("187 =======================================");
    this.getDigitalCertificateAsIntegers();
    
    /*
     * PART 6
     */
    System.out.println("206 =======================================");
    
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
    debug("### Initial p = "+p);
    debug("### Initial q = "+q);
  }
  private int generateRandomNumber(boolean verbose) {
    int p = 1;
    print(verbose,"Generating a random 7-bit integer:");
    print(verbose,"n = 1 (because last bit is 1, 1*2^0=1)");
    for(int i=1; i<6; i++) {
      int temp = Math.abs(randomizer.nextInt());
      print(verbose,"Random number "+i+" generated: "+temp);
      print(verbose,"Least significant bit of "+temp+" is "+temp%2);
      print(verbose,"n = "+p+" + "+(int)Math.pow(2, i)*(temp%2));
      p = p + (int)Math.pow(2, i)*(temp%2);
      print(verbose,"n = "+p);
    }
    print(verbose,"Most significant bit of random number is always 1.");
    print(verbose,"n = "+p+" + "+(int)Math.pow(2, 6));
    print(verbose,"n = "+(p+(int)Math.pow(2, 6)));
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
      this.debug("### p = generateRandomNumber("+p+")");
    }
    while(!this.isPrime(q, false)) {
      do {
        q = this.generateRandomNumber(false);
      } while (pastvalues.contains(q));
      pastvalues.add(q);
      this.debug("### q = generateRandomNumber("+q+")");
    }
    this.isPrime(p,true);
    this.print(true,"### final p = "+p);
    this.print(true,"### final q = "+q);
  }
  private boolean isPrime(int n, boolean verbose) {
    //Tests if the given int is a prime number by modified Miller-Rabin
    print(verbose,"Testing if "+n+" is prime:");
    List<Integer> pastAvalues = new ArrayList<Integer>();
    /*
    for(int i=0; i<20; i++) {
      int a;
      do {
        a = Math.abs(randomizer.nextInt())%n;
      } while(a == 0 || pastAvalues.contains(a));
      pastAvalues.add(a);
      debug(verbose,"Test "+(i+1)+" with a = "+a);
      
      //MODIFY TO BE CORRECT TO ALGORITHM
      if(n%a == 0) {
        print(verbose,n+" is not prime.");
        return false;
      }
    }
    */
    for(int i=3; i<n; i=i+2) {
      if(n%i == 0) {
        this.print(verbose,n+" is not prime, has factor "+i);
        return false;
      }
    }
    this.print(verbose,n+" is probably prime");
    return true;
  }
  
  private void getPublicKey() {
    boolean verbose = true;
    ArrayList<Integer> pastEvalues = new ArrayList<Integer>();
    e = 3;
    while(e<n && !isRelativelyPrime(e,n,true)) {
      e++;
      if(e==n) {
        //No relatively prime value e found
        //Regenerate prime values p, q
        this.print(verbose,"### No relatively prime e found. Regenerating primes p & q.");
        p = this.generateRandomNumber(false);
        q = this.generateRandomNumber(false);
        this.getPrimePQ();
        this.print(verbose,"### New p = "+p);
        this.print(verbose,"### New q = "+q);
        n = p*q;
        this.print(verbose,"### New n = "+n);
        e = 3;
      }
    }
    print(true,"### final e = "+e);
  }
  private boolean isRelativelyPrime(int e, int n, boolean verbose) {
    print(true,"Trying e = "+e);
    //Use Extended Euclidean Algorithm to determine if e is relatively prime
    int big = n;
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
      this.print(verbose,e+" and "+n+" are relatively prime.");
      return true;
    } else {
      this.print(verbose,e+" and "+n+" are not relatively prime.");
      return false;
    }
  }
  private void getPrivateKey() {
    boolean verbose = true;
    int p0 = 0, p1 = 1;
    while(quotient.size()>0) {
      int temp = p1;
      int quot = quotient.remove(0);
      p1 = (p0 - p1*quot)%n;
      print(verbose,"t = "+p0+" - "+temp+"*"+quot+" mod("+n+") = "+p1);
      p0 = temp;
      if(p1<0) {
        print(verbose,"t = "+p1+" mod("+n+") = "+(n+p1));
        p1 = n + p1;
      }
    }
    d = p1;
    print(true,"### final d = "+d);
  }

  private void showAllValues() {
    System.out.println("p = "+p+" ("+getBitRepresentation(p)+")");
    System.out.println("q = "+q+" ("+getBitRepresentation(q)+")");
    System.out.println("n = "+n+" ("+getBitRepresentation(n)+")");
    System.out.println("e = "+e+" ("+getBitRepresentation(e)+")");
    System.out.println("d = "+d+" ("+getBitRepresentation(d)+")");
  }
  private String getBitRepresentation(int x) {
    StringBuilder s = new StringBuilder(Integer.toBinaryString(x));
    for(int b=s.length(); b<32; b++) {
      s.insert(0, "0");
    }
    return s.toString();
  }

  private void getDigitalCertificate() {
    //Determine r
    
    //Determine h(r)
    
    //Determine s
  }
  private void getDigitalCertificateAsIntegers() {
    //Determine h(r)
    
    //Determine s
    
  }



}

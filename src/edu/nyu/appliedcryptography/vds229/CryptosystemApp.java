package edu.nyu.appliedcryptography.vds229;

import java.util.*;

/***
 * This is app uses a [modified] RSA public/private cryptosystem to
 * create digital certificates and perform authentication according to the
 * specifications given by the NYU 3205 Applied Cryptography final project. 
 * @author Vangie
 */
public class CryptosystemApp {
  public static void main(String[] args) {
    new CryptosystemApp().run(); //get out of static context ASAP
  }
  
  /**
   * This is the main program, running through all the steps in the 
   * project specification.
   */
  private void run() {
    //Generate 2 random numbers
    int prime1 = generateRandomNumber(true);
    int prime2 = generateRandomNumber(false);
    System.out.println("### prime1 = "+prime1);
    System.out.println("### prime2 = "+prime2);
    
    //Test if 2 numbers are prime
    //If not, continue generating random numbers until 2 primes are obtained
    isNotPrime(prime1, true);
    while(isNotPrime(prime1, false)) {
      prime1 = generateRandomNumber(false);
      System.out.println("### prime1 = "+prime1);
    }
    while(isNotPrime(prime2, false)) {
      prime2 = generateRandomNumber(false);
      System.out.println("### prime2 = "+prime2);
    }
    
  }
  
  private int generateRandomNumber(boolean verbose) {
    Random randomizer = new Random();
    int p = 1;
    if(verbose) {
      System.out.println("104 =======================================");
      System.out.println("p = 1 (because last bit is 1, 1*2^0=1)");
    }
    for(int i=1; i<6; i++) {
      int temp = Math.abs(randomizer.nextInt());
      if(verbose) {
        System.out.println("Random number "+i+" generated: "+temp);
        System.out.println("Least significant bit of "+temp+" is "+temp%2);
        System.out.println("p = "+p+" + "+(int)Math.pow(2, i)*(temp%2));
      }
      p = p + (int)Math.pow(2, i)*(temp%2);
      if(verbose) {
        System.out.println("p = "+p);
      }
    }
    return p;
  }
  
  /*
   * Tests if the given int is a prime number by modified Miller-Rabin
   */
  private boolean isNotPrime(int number, boolean verbose) {
    if(verbose) {
      System.out.println("119 ======================================");
    }
    return false;
  }
  

}

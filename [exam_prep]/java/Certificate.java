package ro.ase.ism.sap.day2;

import java.util.ArrayList;
import java.util.List;

public class Certificate {
	String name;
	String organization;
	String country;
	String signature;
	
	ArrayList<Byte> publicKey = new ArrayList<>(128);
	
	public Certificate(String name, String organization, String country, String signature) {
		super();
		this.name = name;
		this.organization = organization;
		this.country = country;
		this.signature = signature;
	}
	
	@Override
	public String toString() {
		return this.name + " with signature " + this.signature;
	}

	@Override
	public int hashCode() {
		return this.signature.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		
		if(!(obj instanceof Certificate)) {
			return false;
		}
		
		Certificate other = (Certificate) obj;
		
		return this.name.equals(other.name) && 
				this.signature.equals(other.signature);
	}

	@Override
	protected Object clone() throws CloneNotSupportedException {
		Certificate copy = 
				new Certificate(name, organization, country, signature);
		
		//don't do the shallow copy
		//copy.publicKey = this.publicKey;
		
		//do deep-copy
		copy.publicKey = 
				(ArrayList<Byte>) this.publicKey.clone();
		//alternative
		//copy.publicKey = new ArrayList<>(this.publicKey);
		
		return copy;
	}
	
	public static void main(String[] args) {
		
		BitSet bitSet = new BitSet(32);
		bitSet.set(0); //set to 1 the 1st bit from left to right
		bitSet.set(1, false); //set to 0 the 2nd bit
		
		if(bitSet.get(0)) {
			System.out.println("1st bit is 1");
		}
		else {
			System.out.println("1st bit is 0");
		}
		
		byte seed = (byte) 0b1100_1100;
		for(int i = 0; i < 8; i++) {
			byte mask = (byte) (1 << (7 - i));
			bitSet.set(i, ((seed & mask) != 0));
		}
		
		System.out.println("Bitset:");
		for(int i = 0; i < bitSet.size(); i++) {
			System.out.print(bitSet.get(i) ? 1 : 0);
		}
		
		//3 types of collections
		//List - like a dynamic array
		//Set - like a dynamic array with UNIQUE values
		//Map - like a dictionary with UNIQUE keys
		
		List<Integer> values = new ArrayList<>();
		values.add(23);
		values.add(56);
		values.add(22);
		values.add(56);
		
		System.out.println();
		for(int value : values) {
			System.out.println("List value is " + value);
		}
		
		Set<Integer> uniqueValues = new HashSet<>();
		uniqueValues.add(23);
		uniqueValues.add(56);
		uniqueValues.add(22);
		uniqueValues.add(56);
		
		for(int value : uniqueValues) {
			System.out.println("Unique List value is " + value);
		}
		
		Map<Integer, String> users = new HashMap<>();
		users.put(1, "John");
		users.put(3, "Alice");
		users.put(10, "Bob");
		users.put(1, "Vader");
		
		String username = users.get(10);
		if(username != null) {
			System.out.println("User is " + username);
		}
		else {
			System.out.println("No usee with id 10");
		}
		
		for(Integer key : users.keySet()) {
			System.out.println("User " + users.get(key) + " with id " + key);
		}
		
		//collections and defined models
		Set<Certificate> certificates = new HashSet<>();
		
		certificates.add(
				new Certificate("John", "ISM", "RO", "A312B5AD"));
		certificates.add(
				new Certificate("John", "ISM", "RO", "A312B5AD"));
		
		for(Certificate certificate : certificates) {
			System.out.println(certificate.toString()); 
		}
		
	}
	
}

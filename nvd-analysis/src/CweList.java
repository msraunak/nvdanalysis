/**
 * List of CWEs used by NIST and available to be chosen in the advanced
 * Vulnerability Search. 
 * @author msr4
 */

import java.util.ArrayList;
import java.util.Collections;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedReader;

public class CweList {

	private ArrayList<CWE> wknessListAll;
	private ArrayList<CWE> nistList; // The CWEs that were used by NIST (19 of them);
	private BufferedReader bufReader;
	
	// The text file that has all the categories available in the advanced search option
	private final static String catFileName="cwelist.txt";


	//Default constructor
	public CweList(){
		wknessListAll = new ArrayList<CWE>();
		nistList = new ArrayList<CWE>();
		populateList();
	}
	
	// Getters
	public ArrayList<CWE> getWeaknessListAll(){
		return wknessListAll;
	}	
	public ArrayList<CWE> getNISTList(){
		return nistList;
	}
	
	/** 
	 * Read the text file and populate the source text file. 
	 */
	public void populateList() {
		try {
			bufReader = new BufferedReader(new FileReader(new File(catFileName)));
			String line;
		
			while((line = bufReader.readLine()) != null) {
				processAndAddToCweList(line);
			}
			
		} catch (IOException ioe) {
			System.out.println("Could not open file " + catFileName);
			ioe.printStackTrace();
			System.exit(-1);
			
		}
	}
	
	
	/*
	 * 	Example Line: <option value="CWE-824">Access of Uninitialized Pointer</option>
	 */
	public void processAndAddToCweList(String line) {
		
		CWE cwe;
		String patternRegEx = "^.*(<option.*CWE-)(.*)(\">)(.*)(</option>).*$";
		String id, name;

	    Pattern pattern = Pattern.compile(patternRegEx);
	    Matcher matcher = pattern.matcher(line);
	    if (matcher.matches()) {
	    	try {
	    		id = matcher.group(2);
	    		name = matcher.group(4);
		    	cwe = new CWE(id, name);
		    	this.wknessListAll.add(cwe); // add it to the weaknessList ArrayList
		    	if (cwe.isOneOfNIST19())
		    		this.nistList.add(cwe); // Additionally add it to the nistList

	    	} catch (NumberFormatException nfe) {
	    		System.out.println(line);
	    		System.exit(1);
	    	}
	    } else {
	        System.out.println("NO MATCH in " + line);
	    } 
	}

	/* Sort the lists */
	public void sortTheLists(){
	
		if ( !wknessListAll.isEmpty() )
			Collections.sort(wknessListAll);
		 
		if ( !nistList.isEmpty() )
			Collections.sort(nistList);
	}

	// 	Print the list of CWEs
	public void printAllCWEs(){
		for (CWE cwe: wknessListAll){
			System.out.println(cwe);
		}
	}

	
	// Output the list of CWEs with their number of Vulnerabilities by year in a text file 
	public void printAllCWEsToFile(String fileName){
		
		PrintWriter pw;
		boolean isFirst = true;
		try {
			
			 pw = new PrintWriter( new File(fileName) );
			 // for all the CWE objects in the wknessList
			 for (CWE cwe: wknessListAll){
				 if (isFirst) {
					String headerStr = "CWE-ID \tCWE-Name \tCWE-Type \tIsNIST19 \t"; 
					for( Integer year: cwe.getVulnByYear().keySet()){
							headerStr += "\t" + year;
						}
					System.out.println(headerStr);
					pw.println(headerStr);
					isFirst = false;
				 }
				 System.out.println(cwe.toString()); // the .toString() is opitonal
				 pw.println( cwe.toString() );
			 }
			 pw.close();
		} catch (IOException ioe){
			System.out.println(ioe.getMessage());
		} 
		
	}
	
	// Output the list of 19 CWEs used by NIST with their number of Vulnerabilities by year in a text file
	public void printAllNistCWEsToFile(String fileName){
		
		PrintWriter pw;
		try {
			
			 pw = new PrintWriter( new File(fileName) );
			 for (CWE cwe: nistList){
					pw.println( cwe.toString() );
			 }
			 pw.close();
		} catch (IOException ioe){
			System.out.println(ioe.getMessage());
		} 
		
	}
	
	//	Print the list of CWEs
	public void printAllNISTCWEs(){
		Collections.sort(nistList); // sort the list before printing
		for (CWE cwe: nistList){
			System.out.println(cwe);
		}
	}
	
}

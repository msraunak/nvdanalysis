import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;

import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * The main class to drive the program
 * @author msr4
 */

public class CVSSAnalysis {

	
	public static void main (String[] args){
		
		int begYear, endYear;
		begYear=2008;
		endYear=2016;
		String fileName = "NumOfVulnByYearAndSeverity.txt";
		
		Map <Integer, CVECountBySeverity> cvss2 = new TreeMap<Integer, CVECountBySeverity>(); 
		
	
		
	} // end main

	/** Print all vulnerabilities reported year by year 
	 *  @param Year the beggining year of the data beign printed
	 *  @param Year the end year of the data being printed
	 */
	public static void printTotalVulnReportedInYear(int begYear, int endYear){
	
		Map <Integer,Integer> totalVulnPerYear = new TreeMap<Integer, Integer>();
		
		for (int year=begYear; year<=endYear; year++){
			totalVulnPerYear.put(year, vulnReportedInAYear(year) );
		}
		
		String strYears="";
		String strVulns="";
		for (Integer yr: totalVulnPerYear.keySet() ) {
			strYears =  strYears+ yr +"\t";
			strVulns = strVulns+ totalVulnPerYear.get(yr) + "\t";
		}
			
		System.out.println(strYears);
		System.out.println(strVulns);
		
	}
	
	/**
	 * Search and find out the number of vulnerabilities reported in a year for a particular CWE type
	 * @param cwe Common Weakness Enumeration
	 * @param year Reporting Year
	 */
	public static void searchByCVSSLevelAndYear(CWE cwe, int year) {
			
	String urlString = "";
		
		urlString += "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cwe_id=CWE-" + cwe.getId(); 
		urlString += "&pub_date_start_month=0&pub_date_start_year=" + year;
		urlString += "&pub_date_end_month=11&pub_date_end_year=" + year;
		
		try {

			URL url = new URL(urlString);

			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			
			String strLine = "";
			String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
			Pattern pattern = Pattern.compile(patternRegEx);
		    Matcher matcher;
		    
			while (null != (strLine = br.readLine())) {
				
				matcher = pattern.matcher(strLine);	
				if (matcher.matches()){
					int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
					System.out.println("CWE-"+ cwe.getId() + ": " + cwe.getName() 
										+ ": " + cwe.getType() + ": " + year + ":" + numOfVuln);
					
					//cwe.setNumOfVuln(numOfVuln);
					cwe.addNumVulnInYear(year, numOfVuln);
					break;
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}	
			
	}

	/* Given a particular year, find out the total number of vulnerabilities reported in that year
	 * https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true
	 * &cves=on&pub_date_start_month=0&pub_date_start_year=2009&pub_date_end_month=11&pub_date_end_year=2009
	 * &cvss_version=3&cve_id=
	 */
	public static int vulnReportedInAYear(int year){
		
		String urlString = "";
		urlString += "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on"; 
		urlString += "&pub_date_start_month=0&pub_date_start_year=" + year;
		urlString += "&pub_date_end_month=11&pub_date_end_year=" + year;
				
		try {
				URL url = new URL(urlString);
				BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
				
				String strLine = "";
				String patternRegEx = "(.*)There are <strong>(.*)</strong> matching records(.*)";
				Pattern pattern = Pattern.compile(patternRegEx);
			    Matcher matcher;
			    
				while (null != (strLine = br.readLine())) {
					
					matcher = pattern.matcher(strLine);	
					if (matcher.matches()){
						int numOfVuln = Integer.parseInt(matcher.group(2).replaceAll(",","")); //strip all commas in the matched gropu
						System.out.println(year + ": " + numOfVuln);
						
						return numOfVuln; 
					}
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}	
		return -1;
	}// end method vulnReportedInAYear
	
	
} // end class

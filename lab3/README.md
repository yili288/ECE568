#Yi Li Ng, 1005743741, yili.ng@mail.utoronto.ca
#Jeff Li, 1005802801, jelicj.li@mail.utoronto.ca

### Part 1 Explanation:
A fake HTML form is made with username and password fields for users to input their info. When they fill out the form and click submit, a JS script will execute and populate a URL with the submitted form info, to which they are redirected. 

### Part 2 Explanation:
A script is inputted into the three-digit access code field, such that when a user clicks "Buy", they are redirected to a URL containing their credit card info, which is obtainable with fetching the element's ID. 

### Part 3 Explanation:
Since the contents of the email will be render on the screen after submitting, exploit this by putting a html image tag with the src as the attack url to the message of the email.

### Part 4 Explanation:
Since the contents of the email will be render on the screen after submitting, exploit this by putting javascript and html code that renders the transfer page and clicks the confirm button in the email message.

### Part 5 Explanation:
Since the contents of the email will be render on the screen after submitting, exploit this by putting javascript and html code that renders the main transfer page, specifies an amount to transfer and clicks the submit button in the email message.

### Part 6 Explanation:
The full where clause looks like this WHERE last_name='Smith' OR 'a'='a'. Smith is followed with a closing quote in order to extend the condition of the WEHRE clause. In this case, a condition that executes the WHERE clause always true is added in order to show all entries in the table.

### Part 7 Explanation:
The first step requires the use of 'UPDATE' to set the salary to 999, while the second step requires the use of 'CREATE TRIGGER' to create a trigger. The email to be used is that of 2022 instead of 2024. Both steps require 101 as the userid value before a semicolon and an additional query. 

### Part 8 Explanation:
We use a SELECT query to try to narrow down the pin associated with the credit card number. After trial and error we get to 3318 as the value of the pin. See the SQL input below:
101; SELECT * FROM credit WHERE pin>3317 AND pin<3319 AND cc_number=1234123412341234 --
let menuicn = document.querySelector(".menuicn"); 
let nav = document.querySelector(".navcontainer"); 

menuicn.addEventListener("click", () => { 
	nav.classList.toggle("navclose"); 
})




document.getElementById('showFormBtn').addEventListener('click', function() {
	var form = document.getElementById('crudForm');
	form.style.display = form.style.display === 'none' ? 'block' : 'none';
	form.classList.toggle("hidden"); 
  });

  document.getElementById('crudForm').addEventListener('submit', function(e) {
	e.preventDefault();

	var vehicle = document.getElementById('vehicle').value;
	var type = document.getElementById('type').value;
	var fuelConsumption = document.getElementById('fuel_consumption').value;

	fetch('/add_crud', {
	  method: 'POST',
	  headers: {
		'Content-Type': 'application/json'
	  },
	  body: JSON.stringify({
		vehicle: vehicle,
		type: type,
		fuel_consumption: fuelConsumption
	  })
	})
	.then(response => response.json())
	.then(data => {
	  var newRow = `<tr>
		<td>${data.id}</td>
		<td>${data.vehicle}</td>
		<td>${data.type}</td>
		<td>${data.fuel_consumption}</td>
		<td>
		  <form action="/crud/delete/${data.id}" method="POST" style="display:inline;">
			<button type="submit" class="btn btn-danger btn-sm">Delete</button>
		  </form>
		</td>
	  </tr>`;
	  document.getElementById('crudTableBody').insertAdjacentHTML('beforeend', newRow);

	  // Clear form fields
	  document.getElementById('vehicle').value = '';
	  document.getElementById('type').value = '';
	  document.getElementById('fuel_consumption').value = '';
	  // Hide form after submission
	  document.getElementById('crudForm').style.display = 'none';
	})
	.catch(error => {
	  console.error('Error:', error);
	});
  });



  


  const updateButtons = document.querySelectorAll('.update-btn');

  // Loop through each update button
  updateButtons.forEach(button => {
	  // Add click event listener
	  button.addEventListener('click', () => {
		  // Get entry id from data-entry-id attribute
		  const entryId = button.getAttribute('data-entry-id');
		  
		  // Get corresponding update form
		  const updateForm = document.querySelector(`.update-form[data-entry-id="${entryId}"]`);
		  
		  // Toggle visibility of the update form
		  updateForm.classList.toggle('hidden');
	  });
  });

  function loadContent(page) {
    // Fetch the content of the specified page
    fetch(page)
        .then(response => response.text())
        .then(html => {
            // Replace the content of the 'content' div with the fetched HTML
            document.getElementById('content').innerHTML = html;
        })
        .catch(error => console.error('Error fetching content:', error));
}


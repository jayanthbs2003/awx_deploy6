<?php
$servername = "localhost";
$username = "root";
$password = ""; // default password
$dbname = "virtual_machine";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get POST data securely
$datacenter = $_POST['Datacenter'] ?? '';
$folder = $_POST['Folder'] ?? '';
$cluster = $_POST['Cluster'] ?? '';
$datastore = $_POST['Datastore'] ?? '';
$network = $_POST['Network'] ?? '';
$template = $_POST['Template'] ?? ''; // Changed variable to lowercase
$vm_name = $_POST['vmName'] ?? '';
$location = $_POST['Location'] ?? '';

// Use prepared statement to prevent SQL injection
$sql = "INSERT INTO deployments (datacenter, folder, cluster, datastore, network, template, vm_name, location, deployment_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())";

$stmt = $conn->prepare($sql);
$stmt->bind_param("ssssssss", $datacenter, $folder, $cluster, $datastore, $network, $template, $vm_name, $location);

if ($stmt->execute()) {
    echo "Deployment details saved successfully!";
} else {
    echo "Error: " . $stmt->error;
}

// Close statement and connection
$stmt->close();
$conn->close();
?>

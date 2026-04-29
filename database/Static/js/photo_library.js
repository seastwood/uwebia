async function deleteImage(imageId) {
    if (!confirm("Are you sure? This will remove the image from all pages using it.")) return;

    const response = await fetch(`/library/delete_image/${imageId}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    });

    if (response.ok) {
        location.reload();
    } else {
        alert("Failed to delete image.");
    }
}

async function createFolder() {
    const folderName = prompt("Enter folder name:");
    if (!folderName) return;

    const response = await fetch('/admin/library/create_folder', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ name: folderName })
    });

    if (response.ok) {
        location.reload();
    }
}

// Example for the Upload form (assuming you have a simple file input)
async function handleUpload(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    // If you're inside a folder, append that ID
    // formData.append('folder_id', currentFolderId);

    const response = await fetch('/admin/library/upload', {
        method: 'POST',
        body: formData
    });

    if (response.ok) {
        location.reload();
    }
}
// LGU Alubijid File Management System

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    
    // Sidebar Toggle
    const sidebarToggle = document.querySelector('.sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            
            // Store the state in localStorage
            if (sidebar.classList.contains('collapsed')) {
                localStorage.setItem('sidebar-collapsed', 'true');
            } else {
                localStorage.setItem('sidebar-collapsed', 'false');
            }
        });
        
        // Check localStorage on page load
        if (localStorage.getItem('sidebar-collapsed') === 'true') {
            sidebar.classList.add('collapsed');
        }
    }
    
    // File Upload
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');
    const uploadArea = document.querySelector('.upload-area');
    const uploadBtn = document.querySelector('.upload-btn');
    
    if (uploadForm && fileInput && uploadArea) {
        // File selection through button
        if (uploadBtn) {
            uploadBtn.addEventListener('click', function(e) {
                e.preventDefault();
                fileInput.click();
            });
        }
        
        // Display selected file name
        fileInput.addEventListener('change', function() {
            const fileNameDisplay = document.querySelector('.file-name');
            
            if (fileNameDisplay) {
                if (this.files.length > 0) {
                    fileNameDisplay.textContent = this.files[0].name;
                    fileNameDisplay.classList.remove('text-muted');
                    
                    // Show the upload form fields
                    const uploadFormFields = document.querySelector('.upload-form-fields');
                    if (uploadFormFields) {
                        uploadFormFields.classList.remove('d-none');
                    }
                } else {
                    fileNameDisplay.textContent = 'No file selected';
                    fileNameDisplay.classList.add('text-muted');
                    
                    // Hide the upload form fields
                    const uploadFormFields = document.querySelector('.upload-form-fields');
                    if (uploadFormFields) {
                        uploadFormFields.classList.add('d-none');
                    }
                }
            }
        });
        
        // Drag and drop functionality
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, function(e) {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, function() {
                this.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, function() {
                this.classList.remove('dragover');
            }, false);
        });
        
        uploadArea.addEventListener('drop', function(e) {
            fileInput.files = e.dataTransfer.files;
            
            // Trigger change event
            const event = new Event('change');
            fileInput.dispatchEvent(event);
        }, false);
    }
    
    // File Search & Filter
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    const categoryFilter = document.getElementById('category-filter');
    const dateFilter = document.getElementById('date-filter');
    const sortByFilter = document.getElementById('sort-by');
    
    if (searchForm) {
        // Function to update filter query parameters
        function updateFilters() {
            const urlParams = new URLSearchParams(window.location.search);
            let hasChanges = false;
            
            if (searchInput && searchInput.value !== urlParams.get('search')) {
                urlParams.set('search', searchInput.value);
                hasChanges = true;
            }
            
            if (categoryFilter && categoryFilter.value !== urlParams.get('category')) {
                urlParams.set('category', categoryFilter.value);
                hasChanges = true;
            }
            
            if (dateFilter && dateFilter.value !== urlParams.get('date')) {
                urlParams.set('date', dateFilter.value);
                hasChanges = true;
            }
            
            if (sortByFilter && sortByFilter.value !== urlParams.get('sort')) {
                urlParams.set('sort', sortByFilter.value);
                hasChanges = true;
            }
            
            if (hasChanges) {
                window.location.href = `${window.location.pathname}?${urlParams.toString()}`;
            }
        }
        
        // Add event listeners to form elements
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            updateFilters();
        });
        
        // Add change listeners to filters
        if (categoryFilter) {
            categoryFilter.addEventListener('change', updateFilters);
        }
        
        if (dateFilter) {
            dateFilter.addEventListener('change', updateFilters);
        }
        
        if (sortByFilter) {
            sortByFilter.addEventListener('change', updateFilters);
        }
    }
    
    // Delete confirmation
    const deleteButtons = document.querySelectorAll('.delete-btn');
    
    if (deleteButtons) {
        deleteButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                
                const fileId = this.getAttribute('data-id');
                const fileName = this.getAttribute('data-name');
                
                if (confirm(`Are you sure you want to delete "${fileName}"? This action cannot be undone.`)) {
                    // Create and submit form for deletion
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = `/delete/${fileId}`;
                    document.body.appendChild(form);
                    form.submit();
                }
            });
        });
    }
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const passwordStrengthMeter = document.getElementById('password-strength');
    
    if (passwordInput && passwordStrengthMeter) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            let feedback = '';
            
            // Check password strength
            if (password.length >= 8) {
                strength += 1;
            }
            
            if (password.match(/[A-Z]/)) {
                strength += 1;
            }
            
            if (password.match(/[a-z]/)) {
                strength += 1;
            }
            
            if (password.match(/[0-9]/)) {
                strength += 1;
            }
            
            if (password.match(/[^A-Za-z0-9]/)) {
                strength += 1;
            }
            
            // Update strength meter
            passwordStrengthMeter.className = '';
            
            if (password.length === 0) {
                passwordStrengthMeter.textContent = '';
                return;
            } else if (strength < 2) {
                passwordStrengthMeter.classList.add('text-danger');
                feedback = 'Weak';
            } else if (strength < 4) {
                passwordStrengthMeter.classList.add('text-warning');
                feedback = 'Moderate';
            } else {
                passwordStrengthMeter.classList.add('text-success');
                feedback = 'Strong';
            }
            
            passwordStrengthMeter.textContent = feedback;
        });
    }
    
    // Password matching validation
    if (passwordInput && confirmPasswordInput) {
        function validatePasswordMatch() {
            if (confirmPasswordInput.value && passwordInput.value !== confirmPasswordInput.value) {
                confirmPasswordInput.setCustomValidity('Passwords do not match');
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        }
        
        passwordInput.addEventListener('input', validatePasswordMatch);
        confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    }
    
    // Alert messages auto-close
    const alerts = document.querySelectorAll('.alert');
    
    if (alerts) {
        alerts.forEach(alert => {
            // Add close button
            const closeBtn = document.createElement('button');
            closeBtn.className = 'close';
            closeBtn.innerHTML = '&times;';
            closeBtn.addEventListener('click', function() {
                alert.remove();
            });
            
            alert.prepend(closeBtn);
            
            // Auto-close after 5 seconds
            setTimeout(() => {
                alert.style.opacity = '0';
                setTimeout(() => {
                    alert.remove();
                }, 300);
            }, 5000);
        });
    }
    
    // Category management modal
    const addCategoryBtn = document.getElementById('add-category-btn');
    const editCategoryBtns = document.querySelectorAll('.edit-category-btn');
    const deleteCategoryBtns = document.querySelectorAll('.delete-category-btn');
    const categoryModal = document.getElementById('category-modal');
    const categoryForm = document.getElementById('category-form');
    
    if (categoryModal) {
        // Close modal function
        function closeModal() {
            categoryModal.style.display = 'none';
        }
        
        // Close button
        const closeBtn = categoryModal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', closeModal);
        }
        
        // Click outside to close
        window.addEventListener('click', function(e) {
            if (e.target === categoryModal) {
                closeModal();
            }
        });
        
        // Add category button
        if (addCategoryBtn && categoryForm) {
            addCategoryBtn.addEventListener('click', function() {
                categoryForm.reset();
                categoryForm.action = '';
                categoryForm.elements.action.value = 'add';
                categoryModal.querySelector('.modal-title').textContent = 'Add Category';
                categoryModal.style.display = 'flex';
            });
        }
        
        // Edit category buttons
        if (editCategoryBtns && categoryForm) {
            editCategoryBtns.forEach(btn => {
                btn.addEventListener('click', function() {
                    const categoryId = this.getAttribute('data-id');
                    const categoryName = this.getAttribute('data-name');
                    const categoryDesc = this.getAttribute('data-description') || '';
                    
                    categoryForm.reset();
                    categoryForm.action = '';
                    categoryForm.elements.action.value = 'edit';
                    categoryForm.elements.category_id.value = categoryId;
                    categoryForm.elements.name.value = categoryName;
                    categoryForm.elements.description.value = categoryDesc;
                    
                    categoryModal.querySelector('.modal-title').textContent = 'Edit Category';
                    categoryModal.style.display = 'flex';
                });
            });
        }
        
        // Delete category buttons
        if (deleteCategoryBtns) {
            deleteCategoryBtns.forEach(btn => {
                btn.addEventListener('click', function() {
                    const categoryId = this.getAttribute('data-id');
                    const categoryName = this.getAttribute('data-name');
                    
                    if (confirm(`Are you sure you want to delete "${categoryName}"? This may affect files assigned to this category.`)) {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '';
                        
                        const actionInput = document.createElement('input');
                        actionInput.type = 'hidden';
                        actionInput.name = 'action';
                        actionInput.value = 'delete';
                        
                        const idInput = document.createElement('input');
                        idInput.type = 'hidden';
                        idInput.name = 'category_id';
                        idInput.value = categoryId;
                        
                        form.appendChild(actionInput);
                        form.appendChild(idInput);
                        document.body.appendChild(form);
                        form.submit();
                    }
                });
            });
        }
    }
});

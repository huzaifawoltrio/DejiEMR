# /app/utils/cloudinary_util.py
import cloudinary
import cloudinary.uploader
import os
from flask import current_app
from werkzeug.utils import secure_filename
import uuid

class CloudinaryManager:
    """Utility class for handling Cloudinary operations."""
    
    def __init__(self, app=None):
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Cloudinary with app config."""
        cloudinary.config(
            cloud_name=app.config.get('CLOUDINARY_CLOUD_NAME'),
            api_key=app.config.get('CLOUDINARY_API_KEY'),
            api_secret=app.config.get('CLOUDINARY_API_SECRET'),
            secure=True
        )
    
    def upload_profile_picture(self, file, user_id, user_type):
        """
        Upload profile picture to Cloudinary.
        
        Args:
            file: The file to upload
            user_id: ID of the user
            user_type: Type/role of the user
            
        Returns:
            dict: Contains upload result with 'success', 'url', 'public_id' or 'error'
        """
        if not file or file.filename == '':
            return {'success': False, 'error': 'No file provided'}
        
        if not self._is_allowed_file(file.filename):
            return {'success': False, 'error': 'File type not allowed'}
        
        if not self._is_valid_file_size(file):
            return {'success': False, 'error': 'File size exceeds 5MB limit'}
        
        try:
            # Generate unique filename
            unique_filename = f"{user_type}_{user_id}_{uuid.uuid4().hex}"
            secure_name = secure_filename(unique_filename)
            
            # Upload to Cloudinary
            upload_result = cloudinary.uploader.upload(
                file,
                public_id=f"profile_pictures/{secure_name}",
                folder="profile_pictures",
                transformation=[
                    {'width': 500, 'height': 500, 'crop': 'fill'},
                    {'quality': 'auto'},
                    {'format': 'auto'}
                ]
            )
            
            return {
                'success': True,
                'url': upload_result.get('secure_url'),
                'public_id': upload_result.get('public_id')
            }
            
        except Exception as e:
            current_app.logger.error(f"Cloudinary upload error: {str(e)}")
            return {'success': False, 'error': 'Failed to upload image'}
    
    def upload_patient_document(self, file, patient_id, uploader_id, description=None):
        """
        Upload patient document to Cloudinary.
        
        Args:
            file: The file to upload
            patient_id: ID of the patient
            uploader_id: ID of the user uploading
            description: Optional description
            
        Returns:
            dict: Contains upload result with 'success', 'url', 'public_id', 'format', 'bytes' or 'error'
        """
        if not file or file.filename == '':
            return {'success': False, 'error': 'No file provided'}
        
        if not self._is_valid_document_file(file.filename):
            return {'success': False, 'error': 'File type not allowed'}
        
        if not self._is_valid_document_size(file):
            return {'success': False, 'error': 'File size exceeds 10MB limit'}
        
        try:
            # Extract file extension from original filename - THIS IS THE KEY FIX
            original_extension = self._get_file_extension(file.filename)
            
            # Generate unique filename
            unique_filename = f"patient_{patient_id}_doc_{uuid.uuid4().hex}"
            secure_name = secure_filename(unique_filename)
            
            # Determine the correct resource type based on file extension
            file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            
            # Set resource type based on file type
            if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']:
                resource_type = "image"
            elif file_extension in ['mp4', 'avi', 'mov', 'wmv', 'mkv']:
                resource_type = "video"
            else:
                # For PDFs, documents, and other files
                resource_type = "raw"
            
            current_app.logger.info(f"Uploading file with extension '{file_extension}' as resource_type '{resource_type}'")
            
            # Upload to Cloudinary with the correct resource type
            upload_result = cloudinary.uploader.upload(
                file,
                public_id=f"patient_documents/{secure_name}",
                folder="patient_documents",
                resource_type=resource_type,
                tags=[f"patient_{patient_id}", f"uploader_{uploader_id}"]
            )
            
            # Use original file extension instead of Cloudinary's format
            # This ensures we always have a valid file_type
            cloudinary_format = upload_result.get('format')
            final_format = original_extension if original_extension else cloudinary_format
            
            current_app.logger.info(f"Upload successful. Cloudinary format: '{cloudinary_format}', Using format: '{final_format}'")
            
            return {
                'success': True,
                'url': upload_result.get('secure_url'),
                'public_id': upload_result.get('public_id'),
                'format': final_format,  # Use the extracted extension
                'bytes': upload_result.get('bytes', 0),
                'resource_type': resource_type
            }
            
        except Exception as e:
            current_app.logger.error(f"Cloudinary document upload error: {str(e)}")
            return {'success': False, 'error': 'Failed to upload document'}
    
    def delete_profile_picture(self, public_id):
        """
        Delete profile picture from Cloudinary.
        
        Args:
            public_id: The Cloudinary public ID of the image to delete
            
        Returns:
            dict: Contains 'success' and optionally 'error'
        """
        try:
            result = cloudinary.uploader.destroy(public_id)
            return {'success': result.get('result') == 'ok'}
        except Exception as e:
            current_app.logger.error(f"Cloudinary delete error: {str(e)}")
            return {'success': False, 'error': 'Failed to delete image'}
    
    def delete_patient_document(self, public_id, resource_type=None):
        """
        Delete patient document from Cloudinary.
        
        Args:
            public_id: The Cloudinary public ID of the document to delete
            resource_type: The resource type ('image', 'video', 'raw') - if None, will try all types
            
        Returns:
            dict: Contains 'success' and optionally 'error'
        """
        try:
            if resource_type:
                # If we know the resource type, delete directly
                result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
                return {'success': result.get('result') == 'ok'}
            else:
                # Try deleting with different resource types
                for res_type in ['raw', 'image', 'video']:
                    try:
                        result = cloudinary.uploader.destroy(public_id, resource_type=res_type)
                        if result.get('result') == 'ok':
                            return {'success': True}
                    except Exception:
                        continue
                
                return {'success': False, 'error': 'Document not found or failed to delete'}
        except Exception as e:
            current_app.logger.error(f"Cloudinary document delete error: {str(e)}")
            return {'success': False, 'error': 'Failed to delete document'}
    
    def _get_file_extension(self, filename):
        """Extract file extension from filename."""
        if not filename or '.' not in filename:
            return None
        return filename.rsplit('.', 1)[1].lower()
    
    def _is_allowed_file(self, filename):
        """Check if file extension is allowed for profile pictures."""
        if not filename:
            return False
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    
    def _is_valid_file_size(self, file):
        """Check if file size is within limits for profile pictures (5MB)."""
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        return file_size <= 5 * 1024 * 1024  # 5MB limit
    
    def _is_valid_document_file(self, filename):
        """Check if document file extension is allowed."""
        if not filename:
            return False
        allowed_extensions = {
            'pdf', 'doc', 'docx', 'txt', 'rtf',  # Documents
            'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp',  # Images
            'mp4', 'avi', 'mov', 'wmv', 'mkv',  # Videos
            'xls', 'xlsx', 'csv',  # Spreadsheets
            'ppt', 'pptx'  # Presentations
        }
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    
    def _is_valid_document_size(self, file):
        """Check if document file size is within limits (10MB)."""
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        return file_size <= 10 * 1024 * 1024  # 10MB limit

# Create a single instance
cloudinary_manager = CloudinaryManager()
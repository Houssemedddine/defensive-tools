#!/usr/bin/env python3
"""
Steganography Tool
Hides text messages inside images using LSB (Least Significant Bit) encoding.
"""

import os
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

class SteganographyTool:
    def __init__(self):
        self.delimiter = "$$EOF$$"

    def _str_to_bin(self, message):
        """Convert string to binary string"""
        return ''.join(format(ord(char), '08b') for char in message)

    def _bin_to_str(self, binary_str):
        """Convert binary string to string"""
        chars = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            chars.append(chr(int(byte, 2)))
        return ''.join(chars)

    def hide_message(self, image_path, message, output_path):
        """
        Hide a message inside an image.
        
        Args:
            image_path (str): Path to source image
            message (str): Text message to hide
            output_path (str): Path to save encoded image
            
        Returns:
            dict: {success: bool, message: str}
        """
        if not HAS_PIL:
            return {"success": False, "message": "Pillow (PIL) library not found. Please install it with: pip install Pillow"}

        try:
            # Append delimiter to message
            full_message = message + self.delimiter
            binary_message = self._str_to_bin(full_message)
            
            with Image.open(image_path) as img:
                # Convert to RGB to ensure 3 channels
                img = img.convert('RGB')
                pixels = img.load()
                width, height = img.size
                
                if len(binary_message) > width * height * 3:
                    return {"success": False, "message": "Message too long for this image."}
                
                data_index = 0
                data_len = len(binary_message)
                
                # Create a specific copy to save
                encoded_img = img.copy()
                pixels = encoded_img.load()
                
                for y in range(height):
                    for x in range(width):
                        if data_index < data_len:
                            r, g, b = pixels[x, y]
                            
                            # Modify LSB of Red
                            if data_index < data_len:
                                r = (r & ~1) | int(binary_message[data_index])
                                data_index += 1
                                
                            # Modify LSB of Green
                            if data_index < data_len:
                                g = (g & ~1) | int(binary_message[data_index])
                                data_index += 1
                                
                            # Modify LSB of Blue
                            if data_index < data_len:
                                b = (b & ~1) | int(binary_message[data_index])
                                data_index += 1
                                
                            pixels[x, y] = (r, g, b)
                        else:
                            break
                    if data_index >= data_len:
                        break
                
                # Save as PNG to avoid compression artifacts destroying the LSB
                # Force .png extension if not present
                if not output_path.lower().endswith('.png'):
                    output_path += '.png'
                    
                encoded_img.save(output_path, 'PNG')
                return {"success": True, "message": f"Message hidden successfully! Saved to: {output_path}"}
                
        except Exception as e:
            return {"success": False, "message": f"Error hiding message: {str(e)}"}

    def extract_message(self, image_path):
        """
        Extract a message from an image.
        
        Args:
            image_path (str): Path to image
            
        Returns:
            dict: {success: bool, message: str, data: str}
        """
        if not HAS_PIL:
            return {"success": False, "message": "Pillow (PIL) library not found.", "data": ""}

        try:
            with Image.open(image_path) as img:
                img = img.convert('RGB')
                pixels = img.load()
                width, height = img.size
                
                binary_data = ""
                
                for y in range(height):
                    for x in range(width):
                        r, g, b = pixels[x, y]
                        binary_data += str(r & 1)
                        binary_data += str(g & 1)
                        binary_data += str(b & 1)
                
                # Convert to string to check for delimiter
                # We can do this in chunks to be faster, but for simple tool this is fine
                # Optimization: check every 8 bits? No, delimiter might be offset?
                # Actually, we encoded 3 bits per pixel.
                
                # Let's reconstruct bytes
                all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
                decoded_str = ""
                
                for byte in all_bytes:
                    if len(byte) < 8: break
                    char = chr(int(byte, 2))
                    decoded_str += char
                    
                    if decoded_str.endswith(self.delimiter):
                        return {
                            "success": True, 
                            "message": "Message extracted successfully.", 
                            "data": decoded_str[:-len(self.delimiter)]
                        }
                
                return {"success": False, "message": "No hidden message found (delimiter not found).", "data": ""}
                
        except Exception as e:
            return {"success": False, "message": f"Error extracting message: {str(e)}", "data": ""}

import ast
import linecache
from pathlib import Path
from typing import Any, Dict

from patchguard.domain.models import AttackEvents

class RuntimeContextExtractor:

   
   
    def extract_context(self,event: AttackEvents)-> Dict[str, Any]:
        """
        Extracts the runtime context from the given AttackEvents object.

        Args:
            event (AttackEvents): The AttackEvents object containing the attack information.

        Returns:
            Dict[str, Any]: A dictionary containing the extracted runtime context.
        """

        file_path = Path(event.caller_file)

        if not file_path.exists() or not file_path.is_file():       # if the file does not exist or is not a file, return an error message
            return {
                "file_path": event.caller_file,
                "target_function":event.caller_function,
                "line_number": event.line_number,
                "function_source": "",
                "surrounding_lines":"",
                "error": f"File not found: {event.caller_file}"
            }
        try:

            full_source = file_path.read_text()
        except Exception as e:   # if there is an error reading the file, return an error message
            return { 
                "file_path": event.caller_file, 
                "target_function": event.caller_function, 
                "line_number": event.line_number, 
                "function_source": "", "surrounding_lines": "",
                "error": f"Failed to read file: {e}",
            }
        function_source = self._extract_enclosing_function(full_source, event.line_number)
        surrounding_lines = self._extract_surrounding_lines(event.caller_file,event.line_number)
        # Return the extracted context as a dictionary
        return { 
            "file_path": event.caller_file, 
            "target_function": event.caller_function, 
            "line_number": event.line_number, 
            "full_source": full_source, 
            "function_source": function_source, 
            "surrounding_lines": surrounding_lines,
              }

    
    
    
    
    def _extract_enclosing_function(self,source_code:str,line_number:int)->str:
        """
        Extracts the source code of the function that encloses the specified line number.

        Args:
            source_code (str): The full source code of the file.
            line_number (int): The line number to find the enclosing function for.

        Returns:
            str: The source code of the enclosing function, or an empty string if not found.
        """

        try:
            tree = ast.parse(source_code)

            for node in ast.walk(tree):

                if isinstance(node, (ast.FunctionDef,ast.AsyncFunctionDef)):
                    start_line = getattr(node, 'lineno', 0)
                    end_line = getattr(node, 'end_lineno', start_line)


                    if start_line <= line_number <= end_line:
                        lines = source_code.splitlines()
                        return "\n".join(lines[start_line - 1:end_line])

        except Exception:
            pass
        return ""
    
    
    
    
    
    def _extract_surrounding_lines(self,file_path:str,line_number:int,window:int=5)->str:
        """
        Extracts the lines surrounding the specified line number from the given file.

        Args:
            file_path (str): The path to the file.
            line_number (int): The line number to extract surrounding lines for.
            window (int): The number of lines to include before and after the specified line.

        Returns:
            str: A string containing the surrounding lines, with the specified line highlighted.
            """

        start=max(1, line_number - window)
        end=line_number + window
        extracted=[]


        for line_no in range(start, end + 1):
            line=linecache.getline(file_path, line_no)
            if line:
                marker=">>>" if line_no == line_number else "    "
                extracted.append(f"{marker} {line_no}: {line.rstrip()}")

        return "\n".join(extracted) 